package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"

	check "github.com/adevinta/vulcan-check-sdk"
	"github.com/adevinta/vulcan-check-sdk/state"
	report "github.com/adevinta/vulcan-report"
)

var (
	checkName = "wpscan-check"

	lowImpactRe    = regexp.MustCompile(`(?i)Crypto|Timing|Enumeration`)
	mediumImpactRe = regexp.MustCompile(`(?i)DoS|Denial of Service|Unauthorized|Authenticated|Redirect|Privilege Escalation`)
	highImpactRe   = regexp.MustCompile(`(?i)XSS|CSRF|Cross-Site|SQL|RCE|Remote Code Execution|CSRF|Traversal|Injection|Bypass`)
)

func main() {
	run := func(ctx context.Context, target string, optJSON string, state state.State) error {
		logger := check.NewCheckLog(checkName)
		if target == "" {
			return fmt.Errorf("check target missing")
		}

		token := os.Getenv("WPVULNDB_API_TOKEN")
		if token == "" {
			return fmt.Errorf("missing Wordpress Vulnerability Database API token")
		}

		url, ok := resolveTarget(target)
		if !ok {
			logger.Info("target does not answer to http or https")
			return nil
		}

		wpScanReport, err := RunWpScan(ctx, logger, target, url, token)
		if err != nil {
			return err
		}

		addVulnsToState(state, wpScanReport)
		return nil
	}

	c := check.NewCheckFromHandler(checkName, run)
	c.RunAndServe()
}

func resolveTarget(target string) (string, bool) {
	u := fmt.Sprintf("://%s/", target)
	t := "https" + u

	_, err := http.Get(t)
	if err == nil {
		return t, true
	}

	t = "http" + u
	_, err = http.Get(t)
	if err != nil {
		return "", false
	}

	return t, true
}

func addVulnsToState(state state.State, r *WpScanReport) {
	// Add informational vulnerability indicating the WordPress version.
	if r.Version.Number != "" {
		wpDetected := report.Vulnerability{
			Summary: "WordPress Detected",
			Details: fmt.Sprintf("It has been detected, with %v%% confidence, that the WordPress version is %v.", r.Version.Confidence, r.Version.Number),
			Score:   report.SeverityThresholdNone,
			// ImpactDetails: "Informational information about the detected WordPress version.",
		}
		if len(r.InterestingFindings) > 0 {
			res := buildResourcesForFindings(r.InterestingFindings)
			wpDetected.Resources = []report.ResourcesGroup{res}
		}
		state.AddVulnerabilities(wpDetected)
	}

	addVulns(state, r.Version.Vulnerabilities)
	addVulns(state, r.MainTheme.Vulnerabilities)
	addVulns(state, r.MainTheme.Version.Vulnerabilities)

	for name, pl := range r.Plugins {
		addPluginVulns(state, pl.Vulnerabilities, name, pl.Version)
	}

}

func getImpact(summary string) (float32, string) {
	if highImpactRe.MatchString(summary) {
		return report.SeverityThresholdHigh, fmt.Sprintf("Matched with regexp: /%v/i.", highImpactRe.String())
	}

	if mediumImpactRe.MatchString(summary) {
		return report.SeverityThresholdMedium, fmt.Sprintf("Matched with regexp: /%v/i.", mediumImpactRe.String())

	}

	if lowImpactRe.MatchString(summary) {
		return report.SeverityThresholdLow, fmt.Sprintf("Matched with regexp: /%v/i.", lowImpactRe.String())
	}

	return report.SeverityThresholdNone, fmt.Sprintf("Did not match with any regexp of higher impact.")
}

func addVulns(state state.State, src []Vulnerability) {
	for _, v := range src {
		impact, _ := getImpact(v.Title)

		vuln := report.Vulnerability{
			Summary:    v.Title,
			Score:      impact,
			References: v.References.URL,
		}
		if v.FixedIn != "" {
			vuln.Recommendations = []string{fmt.Sprintf("Update WordPress to version %v.", v.FixedIn)}
		}
		state.AddVulnerabilities(vuln)
	}
}

func addPluginVulns(state state.State, src []Vulnerability, plugin string, version *PluginVersion) {
	for _, v := range src {
		title := strings.TrimSpace(v.Title)
		var (
			impact float32
			ok     bool
		)
		impact, ok = pluginVulnScores[title]
		if !ok {
			impact, _ = getImpact(v.Title)
		}
		vuln := report.Vulnerability{
			Summary:    "WordPress plugin " + title,
			Score:      impact,
			References: v.References.URL,
		}
		if v.FixedIn != "" {
			if version != nil {
				vuln.Recommendations = []string{fmt.Sprintf("Update WordPress plugin %s from version %s to version %s.", plugin, version.Number, v.FixedIn)}
			} else {
				vuln.Recommendations = []string{fmt.Sprintf("Check if the WordPress plugin %s version is at least %s.", plugin, v.FixedIn)}
			}
		}

		state.AddVulnerabilities(vuln)
	}
}

func buildResourcesForFindings(f []InterestingFinding) report.ResourcesGroup {
	if len(f) < 1 {
		return report.ResourcesGroup{}
	}
	g := report.ResourcesGroup{
		Name:   "findings",
		Header: []string{"finding", "found by"},
	}
	g.Rows = []map[string]string{}
	for _, f := range f {
		g.Rows = append(g.Rows, map[string]string{
			"finding":  f.ToS,
			"found by": f.FoundBy,
		})
	}
	return g
}
