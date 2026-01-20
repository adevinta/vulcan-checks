/*
Copyright 2023 Schibsted
*/

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	check "github.com/adevinta/vulcan-check-sdk"
	"github.com/adevinta/vulcan-check-sdk/helpers"
	checkstate "github.com/adevinta/vulcan-check-sdk/state"
	report "github.com/adevinta/vulcan-report"
)

const codeScanningAlertsAPIPath = "/api/v3/repos/OWNER/REPO/code-scanning/alerts"

type SASTFindings struct {
	Number           int         `json:"number"`
	CreatedAt        time.Time   `json:"created_at"`
	UpdatedAt        time.Time   `json:"updated_at"`
	URL              string      `json:"url"`
	HTMLURL          string      `json:"html_url"`
	State            string      `json:"state"`
	FixedAt          interface{} `json:"fixed_at"`
	DismissedBy      interface{} `json:"dismissed_by"`
	DismissedAt      interface{} `json:"dismissed_at"`
	DismissedReason  interface{} `json:"dismissed_reason"`
	DismissedComment interface{} `json:"dismissed_comment"`
	Rule             struct {
		ID                    string   `json:"id"`
		Severity              string   `json:"severity"`
		SecuritySeverityLevel *string  `json:"security_severity_level"`
		Tags                  []string `json:"tags"`
		Description           string   `json:"description"`
		FullDescription       string   `json:"full_description"`
		Help                  string   `json:"help"`
		HelpURI               string   `json:"help_uri"`
		Name                  string   `json:"name"`
	} `json:"rule"`
	Tool struct {
		Name    string      `json:"name"`
		GUID    interface{} `json:"guid"`
		Version string      `json:"version"`
	} `json:"tool"`
	MostRecentInstance struct {
		Ref         string `json:"ref"`
		AnalysisKey string `json:"analysis_key"`
		Category    string `json:"category"`
		Environment string `json:"environment"`
		State       string `json:"state"`
		CommitSha   string `json:"commit_sha"`
		Message     struct {
			Text string `json:"text"`
		} `json:"message"`
		Location struct {
			Path        string `json:"path"`
			StartLine   int    `json:"start_line"`
			EndLine     int    `json:"end_line"`
			StartColumn int    `json:"start_column"`
			EndColumn   int    `json:"end_column"`
		} `json:"location"`
		HTMLURL         string   `json:"html_url"`
		Classifications []string `json:"classifications"`
	} `json:"most_recent_instance"`
	InstancesURL string `json:"instances_url"`
}

var (
	checkName = "vulcan-github-sast-findings"
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
		intermittent := strings.Replace(codeScanningAlertsAPIPath, "OWNER", org, 1)
		githubURL.Path = strings.Replace(intermittent, "REPO", repo, 1)

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

		var findings []SASTFindings
		cursor := 1
		hasNextPage := true
		for hasNextPage {
			var alertsPage []SASTFindings
			alertsPage, hasNextPage, cursor, err = githubSASTFindings(githubURL.String(), org, repo, cursor)
			if err != nil {
				return err
			}
			findings = append(findings, alertsPage...)
		}

		if len(findings) < 1 {
			return nil
		}

		for _, finding := range findings {
			if finding.MostRecentInstance.State != "open" {
				continue
			}
			if finding.Rule.SecuritySeverityLevel == nil {
				continue
			}
			advisoryScore := scoreSeverity(*finding.Rule.SecuritySeverityLevel)

			rows := map[string]string{
				"SAST Tool":        finding.Tool.Name,
				"Path":             finding.MostRecentInstance.Location.Path,
				"Max. Severity":    fmt.Sprintf("%.2f", advisoryScore),
				"Rule Name":        finding.Rule.Name,
				"Rule Description": finding.Rule.Description,
			}

			vulnerability := report.Vulnerability{
				Summary:          "Static code analysis found a problem in Github Repository",
				Description:      finding.Rule.Name,
				Fingerprint:      helpers.ComputeFingerprint(target, finding.Number),
				AffectedResource: finding.MostRecentInstance.Location.Path,
				Score:            advisoryScore,
				Labels:           []string{"potential", "code", "github"},
				ImpactDetails:    finding.MostRecentInstance.Message.Text,
				Recommendations:  []string{"Analyze and fix the vulnerable code."},
				Resources: []report.ResourcesGroup{
					{
						Name: "Vulnerable Source Code",
						Header: []string{
							"SAST Tool",
							"Path",
							"Max. Severity",
							"Rule Name",
							"Rule Description",
						},
						Rows: []map[string]string{rows},
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
	case "critical":
		return report.SeverityThresholdCritical
	case "high":
		return report.SeverityThresholdHigh
	case "medium":
		return report.SeverityThresholdMedium
	case "low":
		return report.SeverityThresholdLow
	default:
		return report.SeverityThresholdNone
	}
}

func githubSASTFindings(apiURL string, org string, repo string, page int) ([]SASTFindings, bool, int, error) {
	params := url.Values{}
	params.Add("per_page", "100")
	params.Add("state", "open")
	params.Add("page", strconv.Itoa(page))

	intermittent := strings.Replace(codeScanningAlertsAPIPath, "OWNER", org, 1)
	urlPath := strings.Replace(intermittent, "REPO", repo, 1)

	// Create the URL with the parameters
	url := os.Getenv("GITHUB_ENTERPRISE_ENDPOINT") + urlPath

	// Make the GET request
	resp, err := http.Get(url)

	req, err := http.NewRequest(http.MethodGet, apiURL, nil)
	req.Header.Set("Authorization", "Bearer "+os.Getenv("GITHUB_ENTERPRISE_TOKEN"))
	req.Header.Set("Accept", "application/vnd.github+json")
	req.URL.RawQuery = params.Encode()

	client := &http.Client{}
	resp, err = client.Do(req)
	if err != nil {
		return []SASTFindings{}, false, 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return []SASTFindings{}, false, 0, fmt.Errorf("received status %v", resp.Status)
	}

	var findings []SASTFindings
	err = json.NewDecoder(resp.Body).Decode(&findings)
	if err != nil {
		return []SASTFindings{}, false, 0, err
	}

	link := resp.Header.Get("link")
	if link == "" {
		return findings, false, 0, err
	}

	return findings, strings.Contains(link, "rel=\"next\""), page + 1, nil
}
