/*
Copyright 2020 Adevinta
*/

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strconv"
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
		vulnerabilityAlerts(%v) {
			number: totalCount
			pagination: pageInfo { endCursor hasNextPage }
			details: nodes {
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
	SecurityVulnerability struct {
		Advisory ExtendedAdvisory `json:"advisory"`
		Package  struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		VulnerableVersionRange string `json:"vulnerableVersionRange"`
		// NOTE: Github currently always returns the FirstPatchedVersion field empty.
		FirstPatchedVersion string `json:"firstPatchedVersion"`
	} `json:"securityVulnerability"`
}

// ExtendedAdvisory adds the VulnerableVersionRange to the returned structure.
type ExtendedAdvisory struct {
	Summary     string `json:"summary"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	References  []struct {
		URL string `json:"url"`
	} `json:"references"`
	WithdrawnAt            string `json:"withdrawnAt"`
	VulnerableVersionRange string
	// NOTE: Github currently always returns the FirstPatchedVersion field empty.
	FirstPatchedVersion string
}

type dependencyData struct {
	version         string
	ecosystem       string
	vulnCount       int
	maxSeverity     string
	fixedVersion    *semver.Version
	references      string
	referencesCount int
}

var (
	checkName              = "vulcan-github-alerts"
	logger                 = check.NewCheckLog(checkName)
	vulnerableDependencies = report.Vulnerability{
		Summary: "Vulnerable Code Dependencies in Github Repository",
		Description: `Dependencies used by the code in this Github repository have published security vulnerabilities. 
You can find more specific information in the resources table for the repository.`,
		ImpactDetails:   "The vulnerable dependencies may be introducing vulnerabilities into the software that uses them.",
		CWEID:           937,
		Score:           report.SeverityThresholdNone,
		Recommendations: []string{"Update all dependencies to at least the minimum recommended version in the resources table."},
	}
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

		var alerts []Details
		cursor := ""
		hasNextPage := true
		for hasNextPage {
			var alertsPage []Details
			alertsPage, hasNextPage, cursor, err = githubAlerts(githubURL.String(), org, repo, cursor)
			if err != nil {
				return err
			}
			alerts = append(alerts, alertsPage...)
		}

		if len(alerts) < 1 {
			return nil
		}

		dependencies := map[string]*dependencyData{}
		for _, alert := range alerts {
			vuln := alert.SecurityVulnerability

			// If the advisory has been withdrawn, we will ignore it.
			if vuln.Advisory.WithdrawnAt != "" {
				continue
			}

			vuln.Advisory.VulnerableVersionRange = vuln.VulnerableVersionRange
			vuln.Advisory.FirstPatchedVersion = vuln.FirstPatchedVersion
			advisoryScore := scoreSeverity(vuln.Advisory.Severity)

			if dependencies[vuln.Package.Name] != nil {
				dependencies[vuln.Package.Name].vulnCount++
				if advisoryScore > scoreSeverity(dependencies[vuln.Package.Name].maxSeverity) {
					dependencies[vuln.Package.Name].maxSeverity = vuln.Advisory.Severity
				}
			} else {
				dependencies[vuln.Package.Name] = &dependencyData{
					ecosystem:    vuln.Package.Ecosystem,
					maxSeverity:  vuln.Advisory.Severity,
					vulnCount:    1,
					fixedVersion: &semver.Version{},
				}
			}

			// NOTE: We should use the FirstPatchedVersion field whenever available.
			// Currently, we are using the same method that the Github UI seems to be using.
			// We determine the first fixed version if the advisory uses "<" for the upper bound.
			// Otherwise, the first fixed version may not exist or be a minor or major release away.
			splitRange := strings.Split(vuln.Advisory.VulnerableVersionRange, ", ")
			if len(splitRange) > 0 {
				lastVersion := splitRange[len(splitRange)-1]
				// If the vulnerable range has a strict upper bound, then that version is fixed.
				if strings.HasPrefix(lastVersion, "< ") {
					fixedVersion, err := semver.NewVersion(strings.Split(lastVersion, " ")[1])
					if err == nil {
						// If another vulnerabilitu is fixed by a higher version, then that version
						// is required in order to fix all of the vulnerabilities.
						if fixedVersion.GreaterThan(dependencies[vuln.Package.Name].fixedVersion) {
							dependencies[vuln.Package.Name].fixedVersion = fixedVersion
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

		rows := []map[string]string{}
		for dependencyName, dependencyData := range dependencies {
			var recommendedVersion string
			// If we were not able to determine a fixed version, it wil have a nil value.
			if dependencyData.fixedVersion.String() == "0.0.0" {
				recommendedVersion = "Unknown"
			} else {
				recommendedVersion = dependencyData.fixedVersion.String()
			}

			rows = append(rows, map[string]string{
				"Dependency":               dependencyName,
				"Ecosystem":                dependencyData.ecosystem,
				"Vulnerabilities":          fmt.Sprintf("%v", dependencyData.vulnCount),
				"Max. Severity":            dependencyData.maxSeverity,
				"Min. Recommended Version": recommendedVersion,
				"References":               dependencyData.references,
			})
		}

		// We sort the table first by maximum severity, then by number of vulnerabilities
		// and finally by name of the vulnerable dependency in alphabetical order.
		sort.Slice(rows, func(i, j int) bool {
			si := scoreSeverity(rows[i]["Max. Severity"])
			sj := scoreSeverity(rows[j]["Max. Severity"])
			switch {
			case si != sj:
				return si > sj
			case rows[i]["Vulnerabilities"] != rows[j]["Vulnerabilities"]:
				// If for some reason not a number, then it is fine to sort it last.
				vi, _ := strconv.Atoi(rows[i]["Vulnerabilities"])
				vj, _ := strconv.Atoi(rows[j]["Vulnerabilities"])
				return vi > vj
			default:
				return rows[i]["Dependency"] < rows[j]["Dependency"]
			}
		})

		for _, r := range rows {
			affectedResource := fmt.Sprintf("%s:%s", r["Ecosystem"], r["Dependency"])
			vulnerabilityID := computeVulnerabilityID(target, affectedResource, fmt.Sprintf("%v", r))
			vulnerability := report.Vulnerability{
				ID:               vulnerabilityID,
				AffectedResource: affectedResource,
				Score:            scoreSeverity(r["Max. Severity"]),
				Summary:          "Vulnerable Code Dependencies in Github Repository",
				Labels:           []string{"potential", "dependency", "code", "github"},
				Description:      fmt.Sprintf("Dependency [%s] installed by [%s] have published security vulnerabilities.\nYou can find more specific information in the resources table for the repository.", r["Dependency"], r["Ecosystem"]),
				ImpactDetails:    "The vulnerable dependencies may be introducing vulnerabilities into the software that uses them.",
				CWEID:            937,
				Recommendations:  []string{"Update the dependency to at least the minimum recommended version in the resources table."},
				Resources: []report.ResourcesGroup{
					{
						Name: "Vulnerable Dependencies",
						Header: []string{
							"Dependency",
							"Ecosystem",
							"Vulnerabilities",
							"Max. Severity",
							"Min. Recommended Version",
							"References",
						},
						Rows: []map[string]string{r},
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

func computeVulnerabilityID(target, affectedResource string, elems ...interface{}) string {
	h := sha256.New()

	fmt.Fprintf(h, "%s - %s", target, affectedResource)

	for _, e := range elems {
		fmt.Fprintf(h, " - %v", e)
	}

	return fmt.Sprintf("%x", h.Sum(nil))
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

func githubAlerts(graphqlURL string, org string, repo string, cursor string) ([]Details, bool, string, error) {
	// We replace all whitespace with spaces to avoid errors.
	cleanGraphqlQuery := strings.Join(strings.Fields(graphqlQuery), " ")

	filter := fmt.Sprintf(graphqlNumberFilter, graphqlDefaultElements)
	if cursor != "" {
		filter = fmt.Sprintf("%v, %v", filter, fmt.Sprintf(graphqlPageFilter, cursor))
	}
	cleanGraphqlQuery = fmt.Sprintf(cleanGraphqlQuery, org, repo, filter)

	var jsonData = []byte(fmt.Sprintf(`{"query": "%s"}`, cleanGraphqlQuery))

	req, err := http.NewRequest("POST", graphqlURL, bytes.NewBuffer(jsonData))
	req.Header.Set("Authorization", "Bearer "+os.Getenv("GITHUB_ENTERPRISE_TOKEN"))

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return []Details{}, false, "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return []Details{}, false, "", fmt.Errorf("received status %v", resp.Status)
	}

	var alertsResponse alertsData
	err = json.NewDecoder(resp.Body).Decode(&alertsResponse)
	if err != nil {
		return []Details{}, false, "", err
	}

	alerts := alertsResponse.Data.Repository.VulnerabilityAlerts.Details
	hasNextPage := alertsResponse.Data.Repository.VulnerabilityAlerts.Pagination.HasNextPage
	endCursor := alertsResponse.Data.Repository.VulnerabilityAlerts.Pagination.EndCursor
	return alerts, hasNextPage, endCursor, nil
}
