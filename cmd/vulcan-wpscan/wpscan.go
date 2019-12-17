package main

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/adevinta/vulcan-check-sdk/helpers/command"
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
)

// WpScanReport holds the report produced by a wpscan run.
type WpScanReport struct {
	Banner struct {
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
		ReadmeURL          string          `json:"readme_url"`
		ChangelogURL       string          `json:"changelog_url"`
		DirectoryListing   bool            `json:"directory_listing"`
		ErrorLogURL        string          `json:"error_log_url"`
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
func RunWpScan(ctx context.Context, logger *logrus.Entry, target, url, token string) (report *WpScanReport, err error) {
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

	report = &WpScanReport{}

	// Print the wpscan version used.
	output, _, _ := command.Execute(ctx, logger, pathToRuby, append([]string{rubyArgs, wpscanFile, "--version", "--no-banner"})...)
	logger.Infof("wpscan version: %s", output)

	// Wpscan can return following errors:

	// OK               = 0 # No error, scan finished w/o any vulnerabilities found
	// CLI_OPTION_ERROR = 1 # Exceptions raised by OptParseValidator and OptionParser
	// INTERRUPTED      = 2 # Interrupt received
	// ERROR            = 3 # Exceptions raised
	// VULNERABLE       = 4 # The target has at least one vulnerability.
	// Currently, the interesting findings do not count as vulnerabilities.
	exitCode, err := command.ExecuteAndParseJSON(ctx, logger, report, pathToRuby, params...)
	logger.Infof("exit code from wpscan: %d", exitCode)

	return report, err
}
