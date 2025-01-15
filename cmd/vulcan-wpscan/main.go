/*
Copyright 2019 Adevinta
*/

package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"

	check "github.com/adevinta/vulcan-check-sdk"
	"github.com/adevinta/vulcan-check-sdk/helpers"
	checkstate "github.com/adevinta/vulcan-check-sdk/state"
	report "github.com/adevinta/vulcan-report"
)

var (
	checkName = "wpscan-check"

	lowImpactRe    = regexp.MustCompile(`(?i)Crypto|Timing|Enumeration`)
	mediumImpactRe = regexp.MustCompile(`(?i)DoS|Denial of Service|Unauthorized|Authenticated|Redirect|Privilege Escalation`)
	highImpactRe   = regexp.MustCompile(`(?i)XSS|CSRF|Cross-Site|SQL|RCE|Remote Code Execution|CSRF|Traversal|Injection|Bypass`)
)

func main() {
	run := func(ctx context.Context, target, assetType, optJSON string, state checkstate.State) error {
		logger := check.NewCheckLogFromContext(ctx, checkName)

		if target == "" {
			return fmt.Errorf("check target missing")
		}

		isReachable, err := helpers.IsReachable(target, assetType, nil)
		if err != nil {
			logger.Warnf("Can not check asset reachability: %v", err)
		}
		if !isReachable {
			return checkstate.ErrAssetUnreachable
		}

		token := os.Getenv("WPVULNDB_API_TOKEN")
		if token == "" {
			return fmt.Errorf("missing Wordpress Vulnerability Database API token")
		}
		err = os.Setenv("WPSCAN_API_TOKEN", token)
		if err != nil {
			return fmt.Errorf("unable to set WPSCAN_API_TOKEN environment var")
		}

		url, ok := resolveTarget(target)
		if !ok {
			logger.Info("target does not answer to http or https")
			return nil
		}

		wpScanReport, err := RunWpScan(ctx, logger, target, url)
		if err != nil {
			// If the target is not a WordPress site finish the check gracefully.
			if strings.HasPrefix(err.Error(), remoteWebsiteNotWordPress) {
				return nil
			}
			// Inconclusive scan due to WAF protection or authentication required.
			if strings.HasPrefix(err.Error(), targetResponding403) {
				return checkstate.ErrAssetUnreachable
			}
			// Inconclusive scan due to target redirect.
			if strings.HasPrefix(err.Error(), urlRedirects) {
				return checkstate.ErrAssetUnreachable
			}
			// In any other case return the error and finish as failed.
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

func addVulnsToState(state checkstate.State, r *WpScanReport) {
	// Add informational vulnerability indicating the WordPress version.
	addVersionInfoVuln(state, r)

	addVulns(state, r.EffectiveURL, r.Version.Vulnerabilities)
	addVulns(state, r.EffectiveURL, r.MainTheme.Vulnerabilities)
	addVulns(state, r.EffectiveURL, r.MainTheme.Version.Vulnerabilities)

	for name, pl := range r.Plugins {
		if pl.Version != nil {
			addPluginVulns(state, pl.Vulnerabilities, name, pl.Version, r.EffectiveURL)
		}
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

func addVersionInfoVuln(state checkstate.State, r *WpScanReport) {
	if r.Version.Number != "" {
		details := fmt.Sprintf("Version: %v, Confidence %v%%\n", r.Version.Number, r.Version.Confidence)
		details += fmt.Sprintf("Main Theme: %v, Version: %v, Confidence %v%%, Location: %v\n",
			r.MainTheme.Slug, r.MainTheme.Version.Number, r.MainTheme.Confidence, r.MainTheme.Location)

		if len(r.Plugins) > 0 {
			details += "\nPlugins:\n"

			for p, v := range r.Plugins {
				version := "n/a"
				versionConfidence := 0
				if v.Version != nil {
					version = v.Version.Number
					versionConfidence = v.Version.Confidence
				}

				details += fmt.Sprintf(
					"\tPlugin: %v, Confidence: %v%%, Version: %v, Version Confidence: %v%%, Location: %v\n",
					p, v.Confidence, version, versionConfidence, v.Location,
				)
			}
		}

		wpDetected := report.Vulnerability{
			Summary:          "WordPress Detected",
			Details:          details,
			Score:            report.SeverityThresholdNone,
			AffectedResource: r.EffectiveURL,
			Labels:           []string{"issue", "wordpress", "http"},
		}

		if len(r.InterestingFindings) > 0 {
			res := buildResourcesForFindings(r.InterestingFindings)
			wpDetected.Resources = []report.ResourcesGroup{res}
		}

		wpDetected.Fingerprint = helpers.ComputeFingerprint(wpDetected.Details)

		state.AddVulnerabilities(wpDetected)
	}
}

func addVulns(state checkstate.State, affectedResource string, src []Vulnerability) {
	for _, v := range src {
		impact, _ := getImpact(v.Title)

		vuln := report.Vulnerability{
			Summary:          v.Title,
			Score:            impact,
			References:       v.References.URL,
			AffectedResource: affectedResource,
			Labels:           []string{"issue", "wordpress", "http"},
		}

		if v.FixedIn != "" {
			vuln.Recommendations = []string{fmt.Sprintf("Update WordPress to version %v.", v.FixedIn)}
		}

		sort.Strings(v.References.Cve)
		vuln.Fingerprint = helpers.ComputeFingerprint(v.References.Cve)

		state.AddVulnerabilities(vuln)
	}
}

func addPluginVulns(state checkstate.State, src []Vulnerability, plugin string, version *PluginVersion, affectedResource string) {
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
			Summary:          "WordPress plugin " + title,
			Score:            impact,
			References:       v.References.URL,
			AffectedResource: affectedResource,
			Labels:           []string{"issue", "wordpress", "http"},
		}
		if v.FixedIn != "" {
			if version != nil {
				vuln.Recommendations = []string{fmt.Sprintf("Update WordPress plugin %s from version %s to version %s.", plugin, version.Number, v.FixedIn)}
			} else {
				vuln.Recommendations = []string{fmt.Sprintf("Check if the WordPress plugin %s version is at least %s.", plugin, v.FixedIn)}
			}
		}

		sort.Strings(v.References.Cve)
		vuln.Fingerprint = helpers.ComputeFingerprint(v.References.Cve)

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
