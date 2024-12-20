package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

const (
	// GitHubAPI defines the default public Github base URL.
	GitHubAPI = "https://api.github.com"

	// GithubEntepriseAPIPath defines the default Github Enterprise API path.
	GithubEntepriseAPIPath = "/api/v3"

	// DefaultMaxRetries defines the default number of retries for the HTTP request.
	DefaultMaxRetries = 3

	// DefaultBackoffDuration defines the default backoff duration for the HTTP request.
	DefaultBackoffDuration = 5 * time.Second
)

// RSA represents the repository security and analysis information from the GitHub API.
type RSA struct {
	SecurityAndAnalysis struct {
		SecretScanning struct {
			Status string `json:"status"`
		} `json:"secret_scanning"`
		SecretScanningPushProtection struct {
			Status string `json:"status"`
		} `json:"secret_scanning_push_protection"`
		DependabotSecurityUpdates struct {
			Status string `json:"status"`
		} `json:"dependabot_security_updates"`
		SecretScanningNonProviderPatterns struct {
			Status string `json:"status"`
		} `json:"secret_scanning_non_provider_patterns"`
		SecretScanningValidityChecks struct {
			Status string `json:"status"`
		} `json:"secret_scanning_validity_checks"`
	} `json:"security_and_analysis"`
}

func checkDependabot(ctx context.Context, logger *logrus.Entry, target string) ([]map[string]string, error) {
	findingRows := []map[string]string{}

	// Get the repository security information.
	rsa, err := getRepoSecurityWithRetry(ctx, target, DefaultMaxRetries, DefaultBackoffDuration)
	if err != nil {
		return findingRows, err
	}
	if rsa == nil {
		return findingRows, fmt.Errorf("repository security information is nil")
	}
	logger.WithField("security_and_analysis", rsa).Info("repository security and analysis")

	// If the token does not have access to the reposiotry security settings, return an error.
	if rsa.SecurityAndAnalysis.DependabotSecurityUpdates.Status == "" {
		return findingRows, fmt.Errorf("unable to obtain repository security information")
	}

	// Check if Dependabot security updates are enabled.
	if rsa.SecurityAndAnalysis.DependabotSecurityUpdates.Status != "enabled" {
		return findingRows, nil
	}

	link := strings.TrimSuffix(target, ".git") + "/settings/security_analysis"
	row := map[string]string{
		"Control": "Dependabot is enabled",
		"Link":    fmt.Sprintf("(Link)[%s]", link),
	}
	findingRows = append(findingRows, row)

	return findingRows, nil
}

func getRepoSecurityWithRetry(ctx context.Context, target string, maxRetries int, backoff time.Duration) (*RSA, error) {
	var err error
	var result *RSA
	var statusCode int

	for attempt := 0; attempt <= maxRetries; attempt++ {
		result, statusCode, err = getRepoSecurity(ctx, target)
		if err == nil {
			return result, nil
		}
		if !strings.HasPrefix(err.Error(), "unexpected status code") {
			return nil, err
		}

		if statusCode >= 500 || statusCode == 429 {
			time.Sleep(backoff)
			backoff *= 2
			continue
		}
		break
	}

	return nil, fmt.Errorf("failed after %d attempts with error: %w", maxRetries, err)
}

func getRepoSecurity(ctx context.Context, target string) (*RSA, int, error) {
	targetURL, err := url.Parse(target)
	if err != nil {
		return nil, 0, fmt.Errorf("unable to parse target as URL: %w", err)
	}

	targetURL.Path = strings.TrimSuffix(targetURL.Path, ".git")
	splitPath := strings.Split(targetURL.Path, "/")
	org, repo := splitPath[1], splitPath[2]

	var url, token string
	switch {
	// Public Github.
	case targetURL.Host == "github.com":
		url = fmt.Sprintf("%s/repos/%s/%s", GitHubAPI, org, repo)
		token = os.Getenv("GITHUB_API_TOKEN")
	// Private Github Enterprise.
	case strings.HasPrefix(target, os.Getenv("GITHUB_ENTERPRISE_ENDPOINT")):
		url = fmt.Sprintf("%s://%s%s/repos/%s/%s", targetURL.Scheme, targetURL.Host, GithubEntepriseAPIPath, org, repo)
		token = os.Getenv("GITHUB_ENTERPRISE_TOKEN")
	default:
		return nil, 0, fmt.Errorf("unsupported code reposiotry URL: %s", target)
	}

	client := &http.Client{}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, err
	}

	req.Header.Set("Accept", "application/vnd.github+json")
	if token != "" {
		req.Header.Set("Authorization", "token "+token)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, resp.StatusCode, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("failed to read response body: %w", err)
	}
	var rsa RSA
	if err := json.Unmarshal(body, &rsa); err != nil {
		return nil, resp.StatusCode, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return &rsa, resp.StatusCode, nil
}
