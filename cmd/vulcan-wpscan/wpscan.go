/*
Copyright 2019 Adevinta
*/

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/adevinta/vulcan-check-sdk/helpers/command"
)

const (
	NotAWordPressMessage = "The remote website is up, but does not seem to be running WordPress."
)

var (
	pathToRuby = "ruby"
	rubyArgs   = "-W0"
	// Path to wpscan file.
	wpscanFile = "/usr/local/bundle/bin/wpscan"

	// WPScan parameters.
	wpscanBaseParams  = []string{"-f", "json", "--disable-tls-checks", "--url"}
	wpscanForceParams = []string{"--force", "--wp-content-dir", "wp-content"}
	wpscanScopeParams = []string{"--scope"}
	wpscanTokenParams = []string{"--api-token"}
	wpscanUserAgent   = []string{"--user-agent", "Vulcan"}

	// --ignore-main-redirect string matching list.
	// If the target redirects to a different (sub)domain, WPScan tool aborts
	// the execution unless '--ignore-main-redirect' parameter is specified.
	// This is the expected behaviour in most of the cases to avoid having
	// duplicate findings when scanning. For example, if example.com redirects
	// to www.example.com we want vulcan-wpscan to scan only www.example.com.
	// However, there are some subtile cases where we want WPScan tool to try
	// scanning the target even if there is a redirection in place. For example,
	// a site with the Okta Login Plugin may redirect some endpoints to Okta,
	// however WPScan can still scan some content which is not redirected.
	// ignoreMainRedirect will add '--ignore-main-redirect' parameter in the
	// WPScan execution for the redirections containing any of the patterns in
	// the list.
	ignoreMainRedirect = []string{
		"okta.com",
	}
)

// WpScanReport holds the report produced by a wpscan run.
type WpScanReport struct {
	Aborted string `json:"scan_aborted"`
	Banner  struct {
		Description string   `json:"description"`
		Version     string   `json:"version"`
		Authors     []string `json:"authors"`
		SponsoredBy string   `json:"sponsored_by"`
	} `json:"banner"`
	DbUpdateStarted     bool                 `json:"db_update_started"`
	DbFilesUpdated      []string             `json:"db_files_updated"`
	DbUpdateFinished    bool                 `json:"db_update_finished"`
	StartTime           int                  `json:"start_time"`
	StartMemory         int                  `json:"start_memory"`
	TargetURL           string               `json:"target_url"`
	EffectiveURL        string               `json:"effective_url"`
	InterestingFindings []InterestingFinding `json:"interesting_findings"`
	Version             struct {
		Number             string          `json:"number"`
		FoundBy            string          `json:"found_by"`
		Confidence         int             `json:"confidence"`
		InterestingEntries []string        `json:"interesting_entries"`
		Vulnerabilities    []Vulnerability `json:"vulnerabilities"`
	} `json:"version"`
	Plugins   map[string]Plugin `json:"plugins"`
	MainTheme struct {
		Name               string          `json:"name"`
		Location           string          `json:"location"`
		LatestVersion      string          `json:"latest_version"`
		LastUpdated        time.Time       `json:"last_updated"`
		Outdated           bool            `json:"outdated"`
		ChangelogURL       string          `json:"changelog_url"`
		DirectoryListing   bool            `json:"directory_listing"`
		ErrorLogURL        string          `json:"error_log_url"`
		Slug               string          `json:"slug"`
		StyleURL           string          `json:"style_url"`
		StyleName          string          `json:"style_name"`
		StyleURI           string          `json:"style_uri"`
		Description        string          `json:"description"`
		Author             string          `json:"author"`
		AuthorURI          string          `json:"author_uri"`
		Template           string          `json:"template"`
		License            string          `json:"license"`
		LicenseURI         string          `json:"license_uri"`
		Tags               string          `json:"tags"`
		TextDomain         string          `json:"text_domain"`
		FoundBy            string          `json:"found_by"`
		Confidence         int             `json:"confidence"`
		InterestingEntries []string        `json:"interesting_entries"`
		Vulnerabilities    []Vulnerability `json:"vulnerabilities"`
		Version            struct {
			Number             string          `json:"number"`
			Confidence         int             `json:"confidence"`
			FoundBy            string          `json:"found_by"`
			InterestingEntries []string        `json:"interesting_entries"`
			Vulnerabilities    []Vulnerability `json:"vulnerabilities"`
		} `json:"version"`
		Parents []interface{} `json:"parents"`
	} `json:"main_theme"`
	StopTime     int `json:"stop_time"`
	Elapsed      int `json:"elapsed"`
	RequestsDone int `json:"requests_done"`
	UsedMemory   int `json:"used_memory"`
}

// Plugin contains the info returned by wpscan for the detected
// plugins.
type Plugin struct {
	Slug               string          `json:"slug"`
	Location           string          `json:"location"`
	LatestVersion      string          `json:"latest_version"`
	LastUpdated        time.Time       `json:"last_updated"`
	Outdated           bool            `json:"outdated"`
	ReadmeURL          string          `json:"readme_url"`
	ChangelogURL       string          `json:"changelog_url"`
	FoundBy            string          `json:"found_by"`
	Confidence         int             `json:"confidence"`
	InterestingEntries []string        `json:"interesting_entries"`
	Vulnerabilities    []Vulnerability `json:"vulnerabilities"`
	Version            *PluginVersion  `json:"version"`
}

// PluginVersion holds the information about a plugin returned by the wpscan.
type PluginVersion struct {
	Number             string   `json:"number"`
	Confidence         int      `json:"confidence"`
	FoundBy            string   `json:"found_by"`
	InterestingEntries []string `json:"interesting_entries"`
}

type InterestingFinding struct {
	URL                string   `json:"url"`
	ToS                string   `json:"to_s"`
	FoundBy            string   `json:"found_by"`
	Confidence         int      `json:"confidence"`
	InterestingEntries []string `json:"interesting_entries"`
}

// Vulnerability contains the information about a vulnerability found in a wordpress scan.
type Vulnerability struct {
	Title      string `json:"title"`
	FixedIn    string `json:"fixed_in"`
	References struct {
		Cve      []string `json:"cve"`
		URL      []string `json:"url"`
		Wpvulndb []string `json:"wpvulndb"`
	} `json:"references"`
}

// RunWpScan runs wpscan an returns a report with the result of the scan.
func RunWpScan(ctx context.Context, logger *logrus.Entry, target, url, token string) (*WpScanReport, error) {
	params := []string{rubyArgs, wpscanFile}

	resp, err := http.Get(url + "wp-content")
	if err == nil && resp.StatusCode == http.StatusOK {
		params = append(params, wpscanForceParams...)
	}

	wpscanScopeParams = append(wpscanScopeParams, fmt.Sprintf("*.%s", target))
	params = append(params, wpscanScopeParams...)

	wpscanTokenParams = append(wpscanTokenParams, token)
	params = append(params, wpscanTokenParams...)

	wpscanBaseParams = append(wpscanBaseParams, url)
	params = append(params, wpscanBaseParams...)

	params = append(params, wpscanUserAgent...)

	// Print the wpscan version used.
	output, _, _ := command.Execute(ctx, logger, pathToRuby, append([]string{rubyArgs, wpscanFile, "--version", "--no-banner"})...)
	logger.Infof("wpscan version: %s", output)

	return runWpScanCmd(ctx, logger, pathToRuby, params)
}

func runWpScanCmd(ctx context.Context, logger *logrus.Entry, pathToRuby string, params []string) (*WpScanReport, error) {
	// Wpscan returns following exit codes:
	// Source: https://github.com/wpscanteam/CMSScanner/blob/master/lib/cms_scanner/exit_code.rb

	// OK               = 0 # No error, scan finished w/o any vulnerabilities found
	// CLI_OPTION_ERROR = 1 # Exceptions raised by OptParseValidator and OptionParser
	// INTERRUPTED      = 2 # Interrupt received
	// EXCEPTION        = 3 # Unhandled/unexpected Exception occured
	// ERROR            = 4 # Error, scan did not finish
	// VULNERABLE       = 5 # The target has at least one vulnerability

	report := &WpScanReport{}
	stdOut, exitCode, err := command.Execute(ctx, logger, pathToRuby, params...)
	if err != nil {
		logger.Errorf("unable to run the commad with the provided params: %s", err)
		return &WpScanReport{}, err
	}
	err = json.Unmarshal(stdOut, &report)
	if err != nil {
		logger.Errorf("unable to unmarshall the commad output: %s", err)
		return &WpScanReport{}, err
	}
	switch exitCode {
	case 0, 5:
		return report, nil
	case 1, 2, 3:
		return &WpScanReport{}, errors.New(report.Aborted)
	case 4:
		if strings.HasPrefix(report.Aborted, "The URL supplied redirects to") {
			addIgnoreMainRedirectParam := false
			for _, s := range ignoreMainRedirect {
				if strings.Contains(report.Aborted, s) {
					addIgnoreMainRedirectParam = true
					break
				}
			}
			if addIgnoreMainRedirectParam {
				params = append(params, "--ignore-main-redirect")
				return runWpScanCmd(ctx, logger, pathToRuby, params)
			}
		}
		if strings.HasSuffix(report.Aborted, "Please re-try with --random-user-agent") {
			params = append(params, "--random-user-agent")
			return runWpScanCmd(ctx, logger, pathToRuby, params)
		}
		return &WpScanReport{}, errors.New(report.Aborted)
	default:
		return &WpScanReport{}, errors.New("unexpected wpscan command exit code")
	}
}
