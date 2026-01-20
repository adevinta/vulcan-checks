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

const codeScanningAlertsAPIPath = "/api/v3/repos/OWNER/REPO/secret-scanning/alerts"

type SecretAlert struct {
	Number       int       `json:"number"`
	CreatedAt    time.Time `json:"created_at"`
	URL          string    `json:"url"`
	HTMLURL      string    `json:"html_url"`
	LocationsURL string    `json:"locations_url"`
	State        string    `json:"state"`
	Resolution   string    `json:"resolution"`
	ResolvedAt   time.Time `json:"resolved_at"`
	ResolvedBy   struct {
		Login             string `json:"login"`
		ID                int    `json:"id"`
		NodeID            string `json:"node_id"`
		AvatarURL         string `json:"avatar_url"`
		GravatarID        string `json:"gravatar_id"`
		URL               string `json:"url"`
		HTMLURL           string `json:"html_url"`
		FollowersURL      string `json:"followers_url"`
		FollowingURL      string `json:"following_url"`
		GistsURL          string `json:"gists_url"`
		StarredURL        string `json:"starred_url"`
		SubscriptionsURL  string `json:"subscriptions_url"`
		OrganizationsURL  string `json:"organizations_url"`
		ReposURL          string `json:"repos_url"`
		EventsURL         string `json:"events_url"`
		ReceivedEventsURL string `json:"received_events_url"`
		Type              string `json:"type"`
		SiteAdmin         bool   `json:"site_admin"`
	} `json:"resolved_by"`
	SecretType               string `json:"secret_type"`
	SecretTypeDisplayName    string `json:"secret_type_display_name"`
	Secret                   string `json:"secret"`
	PushProtectionBypassedBy struct {
		Login             string `json:"login"`
		ID                int    `json:"id"`
		NodeID            string `json:"node_id"`
		AvatarURL         string `json:"avatar_url"`
		GravatarID        string `json:"gravatar_id"`
		URL               string `json:"url"`
		HTMLURL           string `json:"html_url"`
		FollowersURL      string `json:"followers_url"`
		FollowingURL      string `json:"following_url"`
		GistsURL          string `json:"gists_url"`
		StarredURL        string `json:"starred_url"`
		SubscriptionsURL  string `json:"subscriptions_url"`
		OrganizationsURL  string `json:"organizations_url"`
		ReposURL          string `json:"repos_url"`
		EventsURL         string `json:"events_url"`
		ReceivedEventsURL string `json:"received_events_url"`
		Type              string `json:"type"`
		SiteAdmin         bool   `json:"site_admin"`
	} `json:"push_protection_bypassed_by"`
	PushProtectionBypassed   bool      `json:"push_protection_bypassed"`
	PushProtectionBypassedAt time.Time `json:"push_protection_bypassed_at"`
	ResolutionComment        string    `json:"resolution_comment"`
}

var (
	checkName = "vulcan-github-secrets"
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

		var alerts []SecretAlert
		cursor := 1
		hasNextPage := true
		for hasNextPage {
			var alertsPage []SecretAlert
			alertsPage, hasNextPage, cursor, err = githubSecretAlerts(githubURL.String(), org, repo, cursor)
			if err != nil {
				return err
			}
			alerts = append(alerts, alertsPage...)
		}

		if len(alerts) < 1 {
			return nil
		}

		for _, alert := range alerts {
			if alert.State != "open" {
				continue
			}
			advisoryScore := float32(report.SeverityThresholdHigh)

			rows := map[string]string{
				"Secret Type": alert.SecretTypeDisplayName,
				"GitHub Link": alert.HTMLURL,
			}

			vulnerability := report.Vulnerability{
				Summary:                "Secret Scanning found a secret in a Github Repository",
				Description:            fmt.Sprintf("Secret of type %s leaked", alert.SecretTypeDisplayName),
				Fingerprint:            helpers.ComputeFingerprint(target, alert.SecretType, alert.Number),
				AffectedResource:       fmt.Sprintf("%s | %i", alert.SecretTypeDisplayName, alert.Number),
				AffectedResourceString: target,
				CWEID:                  200,
				Score:                  advisoryScore,
				Labels:                 []string{"secret", "github"},
				ImpactDetails:          "Secret leaked, make sure it's rotated",
				Recommendations:        []string{"Rotate and revoke the leaked secret."},
				Resources: []report.ResourcesGroup{
					{
						Name: "Leaked Secret",
						Header: []string{
							"Secret Type",
							"GitHub Link",
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

func githubSecretAlerts(apiURL string, org string, repo string, page int) ([]SecretAlert, bool, int, error) {
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
		return []SecretAlert{}, false, 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return []SecretAlert{}, false, 0, fmt.Errorf("received status %v", resp.Status)
	}

	var alerts []SecretAlert
	err = json.NewDecoder(resp.Body).Decode(&alerts)
	if err != nil {
		return []SecretAlert{}, false, 0, err
	}

	link := resp.Header.Get("link")
	if link == "" {
		return alerts, false, 0, err
	}

	return alerts, strings.Contains(link, "rel=\"next\""), page + 1, nil
}
