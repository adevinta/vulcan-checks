package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"

	check "github.com/adevinta/vulcan-check-sdk"
	"github.com/adevinta/vulcan-check-sdk/state"
	report "github.com/adevinta/vulcan-report"
)

const graphqlAPIPath = "/api/graphql"
const graphqlQuery = `
query { 
	repository(owner:\"%v\", name:\"%v\") {
		vulnerabilityAlerts(last: 100) {
			number: totalCount
			pagination: pageInfo { endCursor hasNextPage }
			details: nodes {
				securityVulnerability {
					advisory { summary description severity references { url } }
					package { name ecosystem }
					vulnerableVersionRange
					firstPatchedVersion { identifier }
				}
			}
		}
	}
}
`

type alertsData struct {
	Data struct {
		Repository struct {
			VulnerabilityAlerts struct {
				Number     int `json:"number"`
				Pagination struct {
					EndCursor   string `json:"endCursor"`
					HasNextPage bool   `json:"hasNextPage"`
				} `json:"pagination"`
				Details []struct {
					SecurityVulnerability struct {
						Advisory ExtendedAdvisory `json:"advisory"`
						Package  struct {
							Name      string `json:"name"`
							Ecosystem string `json:"ecosystem"`
						} `json:"package"`
						VulnerableVersionRange string `json:"vulnerableVersionRange"`
						FirstPatchedVersion    string `json:"firstPatchedVersion"`
					} `json:"securityVulnerability"`
				} `json:"details"`
			} `json:"vulnerabilityAlerts"`
		} `json:"repository"`
	} `json:"data"`
}

// ExtendedAdvisory adds the VulnerableVersionRange to the returned structure.
type ExtendedAdvisory struct {
	Summary     string `json:"summary"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	References  []struct {
		URL string `json:"url"`
	} `json:"references"`
	VulnerableVersionRange string
	FirstPatchedVersion    string
}

var (
	checkName = "vulcan-github-alerts"
	baseVuln  = report.Vulnerability{
		Description:     "",
		CWEID:           937,
		Score:           report.SeverityThresholdNone,
		Recommendations: []string{"Update the dependency to a version higher than any of the vulnerable version ranges."},
	}
)

func main() {
	run := func(ctx context.Context, target string, optJSON string, state state.State) (err error) {
		if target == "" {
			return errors.New("check target missing")
		}

		targetURL, err := url.Parse(target)
		if err != nil {
			return err
		}

		splitPath := strings.Split(targetURL.Path, "/")
		org, repo := splitPath[1], splitPath[2]

		// TODO: Support multiple authenticated Github Enterprise instances.
		githubURL, err := url.Parse(os.Getenv("GITHUB_ENTERPRISE_ENDPOINT"))
		if err != nil {
			return err
		}
		githubURL.Path = graphqlAPIPath

		cleanGraphqlQuery := strings.Join(strings.Fields(graphqlQuery), " ")
		var jsonData = []byte(fmt.Sprintf(`{"query": "%s"}`, fmt.Sprintf(cleanGraphqlQuery, org, repo)))
		req, err := http.NewRequest("POST", githubURL.String(), bytes.NewBuffer(jsonData))
		req.Header.Set("Authorization", "Bearer "+os.Getenv("GITHUB_ENTERPRISE_TOKEN"))

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		if resp.StatusCode >= 300 {
			return fmt.Errorf("received status %v", resp.Status)
		}

		var alertsResponse alertsData
		err = json.NewDecoder(resp.Body).Decode(&alertsResponse)
		if err != nil {
			return err
		}

		packages := map[string][]ExtendedAdvisory{}
		alerts := alertsResponse.Data.Repository.VulnerabilityAlerts.Details
		for _, alert := range alerts {
			vuln := alert.SecurityVulnerability
			vuln.Advisory.VulnerableVersionRange = vuln.VulnerableVersionRange
			vuln.Advisory.FirstPatchedVersion = vuln.FirstPatchedVersion
			if packages[vuln.Package.Name] != nil {
				packages[vuln.Package.Name] = append(packages[vuln.Package.Name], vuln.Advisory)
			} else {
				packages[vuln.Package.Name] = []ExtendedAdvisory{vuln.Advisory}
			}
		}

		for packageName, packageAdvisories := range packages {
			vuln := baseVuln
			if len(packageAdvisories) > 1 {
				vuln.Summary = fmt.Sprintf(`Multiple vulnerabilities in "%v" dependency`, packageName)
			} else {
				vuln.Summary = fmt.Sprintf(`Vulnerability in "%v" dependency`, packageName)
			}

			var rows []map[string]string
			for i, advisory := range packageAdvisories {
				vuln.Description += advisory.Description
				if i != 0 {
					vuln.Description += "\n\n"
				}

				for _, reference := range advisory.References {
					vuln.References = append(vuln.References, reference.URL)
				}

				advisoryScore := scoreSeverity(advisory.Severity)
				if advisoryScore > vuln.Score {
					vuln.Score = advisoryScore
				}

				if advisory.FirstPatchedVersion == "" {
					advisory.FirstPatchedVersion = "Unknown"
				}
				rows = append(rows, map[string]string{
					"Severity":                 advisory.Severity,
					"Vulnerable Version Range": advisory.VulnerableVersionRange,
					"First Patched Version":    advisory.FirstPatchedVersion,
				})
			}

			sort.Slice(rows, func(i, j int) bool {
				si := scoreSeverity(rows[i]["Severity"])
				sj := scoreSeverity(rows[j]["Severity"])
				return si > sj
			})

			versions := report.ResourcesGroup{
				Name: "Affected Versions",
				Header: []string{
					"Severity",
					"Vulnerable Version Range",
					"First Patched Version",
				},
				Rows: rows,
			}

			vuln.Resources = []report.ResourcesGroup{versions}

			state.AddVulnerabilities(vuln)
		}

		return nil
	}

	c := check.NewCheckFromHandler(checkName, run)

	c.RunAndServe()
}

func scoreSeverity(githubSeverity string) float32 {
	switch githubSeverity {
	case "CRITICAL":
		return report.SeverityThresholdCritical
	case "HIGH":
		return report.SeverityThresholdHigh
	case "MODERATE":
		return report.SeverityThresholdMedium
	case "LOW":
		return report.SeverityThresholdLow
	default:
		return report.SeverityThresholdNone
	}
}
