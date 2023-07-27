/*
Copyright 2020 Adevinta
*/

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
	"strings"

	check "github.com/adevinta/vulcan-check-sdk"
	"github.com/adevinta/vulcan-check-sdk/helpers"
	checkstate "github.com/adevinta/vulcan-check-sdk/state"
	report "github.com/adevinta/vulcan-report"

	semver "github.com/Masterminds/semver/v3"
)

const graphqlAPIPath = "/api/graphql"
const graphqlDefaultElements = 100
const graphqlNumberFilter = "first:%v"
const graphqlPageFilter = `after:\"%v\"`
const graphqlQuery = `
query {
	repository(owner:\"%v\", name:\"%v\") {
		defaultBranchRef { name }
		vulnerabilityAlerts(%v) {
			number: totalCount
			pagination: pageInfo { endCursor hasNextPage }
			details: nodes {
				state
				vulnerableManifestFilename
				vulnerableManifestPath
				vulnerableRequirements
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
			DefaultBranchRef struct {
				Name string `json:"name"`
			} `json:"defaultBranchRef"`
			VulnerabilityAlerts struct {
				Number     int `json:"number"`
				Pagination struct {
					EndCursor   string `json:"endCursor"`
					HasNextPage bool   `json:"hasNextPage"`
				} `json:"pagination"`
				Details []Details `json:"details"`
			} `json:"vulnerabilityAlerts"`
		} `json:"repository"`
	} `json:"data"`
}

// Details contains the details of a security vulnerability.
type Details struct {
	State                      string `json:"state"`
	VulnerableManifestFilename string `json:"vulnerableManifestFilename"`
	VulnerableManifestPath     string `json:"vulnerableManifestPath"`
	VulnerableRequirements     string `json:"vulnerableRequirements"`
	SecurityVulnerability      struct {
		Advisory Advisory `json:"advisory"`
		Package  struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		VulnerableVersionRange string `json:"vulnerableVersionRange"`
		FirstPatchedVersion    struct {
			Identifier string `json:"identifier"`
		} `json:"firstPatchedVersion"`
	} `json:"securityVulnerability"`
}

type Advisory struct {
	Summary     string `json:"summary"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	References  []struct {
		URL string `json:"url"`
	} `json:"references"`
	WithdrawnAt string `json:"withdrawnAt"`
}

type dependencyData struct {
	version         string
	ecosystem       string
	vulnCount       int
	maxSeverity     string
	fixedVersion    *semver.Version
	references      string
	referencesCount int
	paths           map[string]string
}

var (
	checkName = "vulcan-github-alerts"
	logger    = check.NewCheckLog(checkName)
)

func main() {
	run := func(ctx context.Context, target, assetType, optJSON string, state checkstate.State) (err error) {
		if target == "" {
			return errors.New("check target missing")
		}

		targetURL, err := url.Parse(target)
		if err != nil {
			return err
		}

		// We clean the URL to extract the organization and repository names.
		targetURL.Path = strings.TrimSuffix(targetURL.Path, ".git")
		splitPath := strings.Split(targetURL.Path, "/")
		org, repo := splitPath[1], splitPath[2]

		// TODO: Support multiple authenticated Github Enterprise instances.
		githubURL, err := url.Parse(os.Getenv("GITHUB_ENTERPRISE_ENDPOINT"))
		if err != nil {
			return err
		}
		githubURL.Path = graphqlAPIPath

		gitCreds := &helpers.GitCreds{}
		if githubURL.Host != "" && targetURL.Host == githubURL.Host {
			gitCreds.User = "username" // Can be anything except blank.
			gitCreds.Pass = os.Getenv("GITHUB_ENTERPRISE_TOKEN")
		}
		isReachable, err := helpers.IsReachable(target, assetType, gitCreds)
		if err != nil {
			logger.Warnf("Can not check asset reachability: %v", err)
		}
		if !isReachable {
			return checkstate.ErrAssetUnreachable
		}

		alerts, branch, err := githubAlerts(githubURL.String(), org, repo)
		if err != nil {
			return err
		}

		if len(alerts) < 1 {
			return nil
		}

		dependencies := map[string]*dependencyData{}
		for _, alert := range alerts {
			// If the vulnerability no longer exists, we will ignore it.
			if alert.State != "OPEN" {
				continue
			}

			vuln := alert.SecurityVulnerability

			// If the advisory has been withdrawn, we will ignore it.
			if vuln.Advisory.WithdrawnAt != "" {
				continue
			}

			advisoryScore := scoreSeverity(vuln.Advisory.Severity)

			if dependencies[vuln.Package.Name] != nil {
				dependencies[vuln.Package.Name].vulnCount++
				if advisoryScore > scoreSeverity(dependencies[vuln.Package.Name].maxSeverity) {
					dependencies[vuln.Package.Name].maxSeverity = vuln.Advisory.Severity
				}
				dependencies[vuln.Package.Name].paths[alert.VulnerableManifestPath] = alert.VulnerableRequirements
			} else {
				dependencies[vuln.Package.Name] = &dependencyData{
					version:      alert.VulnerableRequirements,
					ecosystem:    vuln.Package.Ecosystem,
					maxSeverity:  vuln.Advisory.Severity,
					vulnCount:    1,
					fixedVersion: &semver.Version{},
					paths:        map[string]string{alert.VulnerableManifestPath: alert.VulnerableRequirements},
				}
			}

			// We should use the FirstPatchedVersion field whenever available.
			if vuln.FirstPatchedVersion.Identifier != "" {
				fixedVersion, err := semver.NewVersion(vuln.FirstPatchedVersion.Identifier)
				if err == nil {
					// If another vulnerability is fixed by a higher version, then that version
					// is required in order to fix all of the vulnerabilities.
					if fixedVersion.GreaterThan(dependencies[vuln.Package.Name].fixedVersion) {
						dependencies[vuln.Package.Name].fixedVersion = fixedVersion
					}
				}
			} else {
				// If not available, we use the same method that the Github UI seems to be using.
				// We determine the first fixed version if the advisory uses "<" for the upper bound.
				// Otherwise, the first fixed version may not exist or be a minor or major release away.
				splitRange := strings.Split(vuln.VulnerableVersionRange, ", ")
				if len(splitRange) > 0 {
					lastVersion := splitRange[len(splitRange)-1]
					// If the vulnerable range has a strict upper bound, then that version is fixed.
					if strings.HasPrefix(lastVersion, "< ") {
						fixedVersion, err := semver.NewVersion(strings.Split(lastVersion, " ")[1])
						if err == nil {
							// If another vulnerability is fixed by a higher version, then that version
							// is required in order to fix all of the vulnerabilities.
							if fixedVersion.GreaterThan(dependencies[vuln.Package.Name].fixedVersion) {
								dependencies[vuln.Package.Name].fixedVersion = fixedVersion
							}
						}
					}
				}
			}

			for i, reference := range vuln.Advisory.References {
				if dependencies[vuln.Package.Name].referencesCount+i != 0 {
					dependencies[vuln.Package.Name].references += ", "
				}
				// References are numbered and linked with markdown in footnote format.
				dependencies[vuln.Package.Name].references += fmt.Sprintf(
					"[%v](%v)",
					dependencies[vuln.Package.Name].referencesCount+1,
					reference.URL,
				)
				dependencies[vuln.Package.Name].referencesCount++
			}
		}

		for dependencyName, dependencyData := range dependencies {
			var recommendedVersion string
			// If we were not able to determine a fixed version, it wil have a nil value.
			if dependencyData.fixedVersion.String() == "0.0.0" {
				recommendedVersion = "Unknown"
			} else {
				recommendedVersion = dependencyData.fixedVersion.String()
			}

			pathSlice := []string{}
			for p, v := range dependencyData.paths {
				pathSlice = append(pathSlice, fmt.Sprintf("[%s](%s/blob/%s/%s)", v, strings.TrimSuffix(target, ".git"), branch, p))
			}
			vulnerability := report.Vulnerability{
				Summary: "Vulnerable Code Dependencies in Github Repository",
				Description: `Dependencies used by the code in this Github repository have published security vulnerabilities. 
You can find more specific information in the resources table for the repository.`,
				Fingerprint:      helpers.ComputeFingerprint(fmt.Sprintf("%v", dependencyData.vulnCount), dependencyData.maxSeverity),
				AffectedResource: fmt.Sprintf("%s:%s", dependencyData.ecosystem, dependencyName),
				Score:            scoreSeverity(dependencyData.maxSeverity),
				Labels:           []string{"potential", "dependency", "code", "github"},
				ImpactDetails:    "The vulnerable dependencies may be introducing vulnerabilities into the software that uses them.",
				CWEID:            937,
				Recommendations:  []string{"Update the dependency to at least the minimum recommended version in the resources table."},
				Resources: []report.ResourcesGroup{
					{
						Name: "Vulnerable Dependencies",
						Header: []string{
							"Paths",
							"Vulnerabilities",
							"Max. Severity",
							"Min. Recommended Version",
							"References",
						},
						Rows: []map[string]string{{
							"Paths":                    strings.Join(pathSlice, ", "),
							"Vulnerabilities":          fmt.Sprintf("%v", dependencyData.vulnCount),
							"Max. Severity":            dependencyData.maxSeverity,
							"Min. Recommended Version": recommendedVersion,
							"References":               dependencyData.references,
						}},
					},
				},
			}
			state.AddVulnerabilities(vulnerability)
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

func githubAlerts(graphqlURL string, org string, repo string) ([]Details, string, error) {
	var alerts []Details
	hasNextPage := true
	branch := ""
	cursor := ""
	for hasNextPage {
		// We replace all whitespace with spaces to avoid errors.
		cleanGraphqlQuery := strings.Join(strings.Fields(graphqlQuery), " ")

		filter := fmt.Sprintf(graphqlNumberFilter, graphqlDefaultElements)
		if cursor != "" {
			filter = fmt.Sprintf("%v, %v", filter, fmt.Sprintf(graphqlPageFilter, cursor))
		}
		cleanGraphqlQuery = fmt.Sprintf(cleanGraphqlQuery, org, repo, filter)

		var jsonData = []byte(fmt.Sprintf(`{"query": "%s"}`, cleanGraphqlQuery))

		req, err := http.NewRequest("POST", graphqlURL, bytes.NewBuffer(jsonData))
		if err != nil {
			return []Details{}, "", err
		}
		req.Header.Set("Authorization", "Bearer "+os.Getenv("GITHUB_ENTERPRISE_TOKEN"))

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			return []Details{}, "", err
		}
		defer resp.Body.Close()

		if resp.StatusCode >= 300 {
			return []Details{}, "", fmt.Errorf("received status %v", resp.Status)
		}

		var alertsResponse alertsData
		err = json.NewDecoder(resp.Body).Decode(&alertsResponse)
		if err != nil {
			return []Details{}, "", err
		}
		branch = alertsResponse.Data.Repository.DefaultBranchRef.Name
		alerts = append(alerts, alertsResponse.Data.Repository.VulnerabilityAlerts.Details...)
		hasNextPage = alertsResponse.Data.Repository.VulnerabilityAlerts.Pagination.HasNextPage
		cursor = alertsResponse.Data.Repository.VulnerabilityAlerts.Pagination.EndCursor
	}
	return alerts, branch, nil
}
