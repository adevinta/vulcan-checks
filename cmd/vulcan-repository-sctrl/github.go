/*
Copyright 2024 Adevinta
*/

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
	// GitHubAPI defines the default public GitHub base URL.
	GitHubAPI = "https://api.github.com"

	// GitHubEntepriseAPIPath defines the default GitHub Enterprise API path.
	GitHubEntepriseAPIPath = "/api/v3"

	// GitHubAutomaticSecurityFixesPath defines the default GitHub Automatic Security Fixes API path.
	GithubAutomaticSecurityFixesPath = "automated-security-fixes"

	// DefaultMaxRetries defines the default number of retries for the HTTP request.
	DefaultMaxRetries = 3

	// DefaultBackoffDuration defines the default backoff duration for the HTTP request.
	DefaultBackoffDuration = 5 * time.Second
)

type DependabotStatus struct {
	Enabled bool `json:"enabled"`
	Paused  bool `json:"paused"`
}

func checkDependabot(ctx context.Context, logger *logrus.Entry, target string) ([]map[string]string, error) {
	findingRows := []map[string]string{}

	// Get the repository security information.
	ds, err := getRepoDependabotStatusWithRetry(ctx, target, DefaultMaxRetries, DefaultBackoffDuration)
	if err != nil {
		return findingRows, err
	}

	if !ds.Enabled {
		logger.WithField("target", target).Debug("Dependabot is not enabled")
		return findingRows, nil
	}

	if ds.Paused {
		logger.WithField("target", target).Debug("Dependabot is paused")
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

func getRepoDependabotStatusWithRetry(ctx context.Context, target string, maxRetries int, backoff time.Duration) (DependabotStatus, error) {
	var err error
	var ds DependabotStatus
	var statusCode int

	for attempt := 0; attempt <= maxRetries; attempt++ {
		ds, statusCode, err = getRepoDependabotStatus(ctx, target)
		if err == nil {
			return ds, nil
		}
		if !strings.HasPrefix(err.Error(), "unexpected status code") {
			return ds, err
		}

		if statusCode >= 500 || statusCode == 429 {
			time.Sleep(backoff)
			backoff *= 2
			continue
		}
		break
	}

	return ds, fmt.Errorf("failed after %d attempts with error: %w", maxRetries, err)
}

func getRepoDependabotStatus(ctx context.Context, target string) (DependabotStatus, int, error) {
	var ds DependabotStatus
	targetURL, err := url.Parse(target)
	if err != nil {
		return ds, 0, fmt.Errorf("unable to parse target as URL: %w", err)
	}

	targetURL.Path = strings.TrimSuffix(targetURL.Path, ".git")
	splitPath := strings.Split(targetURL.Path, "/")
	org, repo := splitPath[1], splitPath[2]

	var url, token string
	switch {
	// Public GitHub.
	case targetURL.Host == "github.com":
		url = fmt.Sprintf("%s/repos/%s/%s/%s", GitHubAPI, org, repo, GithubAutomaticSecurityFixesPath)
		token = os.Getenv("GITHUB_API_TOKEN")
	// Private GitHub Enterprise.
	case strings.HasPrefix(target, os.Getenv("GITHUB_ENTERPRISE_ENDPOINT")):
		url = fmt.Sprintf("%s://%s%s/repos/%s/%s/%s", targetURL.Scheme, targetURL.Host, GitHubEntepriseAPIPath, org, repo, GithubAutomaticSecurityFixesPath)
		token = os.Getenv("GITHUB_ENTERPRISE_TOKEN")
	default:
		return ds, 0, fmt.Errorf("unsupported code repository URL: %s", target)
	}

	client := &http.Client{}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return ds, 0, err
	}

	req.Header.Set("Accept", "application/vnd.github+json")
	if token != "" {
		req.Header.Set("Authorization", "token "+token)
	}

	resp, err := client.Do(req)
	if err != nil {
		return ds, resp.StatusCode, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return ds, resp.StatusCode, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ds, resp.StatusCode, fmt.Errorf("failed to read response body: %w", err)
	}
	if err := json.Unmarshal(body, &ds); err != nil {
		return ds, resp.StatusCode, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return ds, resp.StatusCode, nil
}
