package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/gomarkdown/markdown"
	"github.com/gomarkdown/markdown/parser"
	"github.com/microcosm-cc/bluemonday"
	"github.com/sirupsen/logrus"
	git "gopkg.in/src-d/go-git.v4"
	http "gopkg.in/src-d/go-git.v4/plumbing/transport/http"

	check "github.com/adevinta/vulcan-check-sdk"
	"github.com/adevinta/vulcan-check-sdk/state"
	report "github.com/adevinta/vulcan-report"

	"github.com/adevinta/vulcan-check-sdk/helpers/command"
)

var (
	checkName = "vulcan-snyk"
	logger    = check.NewCheckLog(checkName)
)

func main() {
	run := func(ctx context.Context, target string, optJSON string, state state.State) (err error) {
		logger.WithFields(logrus.Fields{
			"repository": target,
		}).Debug("testing repository")

		if target == "" {
			return errors.New("check target missing")
		}

		targetURL, err := url.Parse(target)
		if err != nil {
			return err
		}

		var auth *http.BasicAuth
		if targetURL.Host == "github.mpi-internal.com" {
			auth = &http.BasicAuth{
				Username: "username", // Can be anything except blank.
				Password: os.Getenv("GITHUB_ENTERPRISE_TOKEN"),
			}
		}

		repoPath := filepath.Join("/tmp", filepath.Base(targetURL.Path))
		err = os.RemoveAll(repoPath)
		if err != nil {
			return err
		}

		if err := os.Mkdir(repoPath, 0755); err != nil {
			return err
		}

		_, err = git.PlainClone(repoPath, false, &git.CloneOptions{
			URL:   target,
			Auth:  auth,
			Depth: 1,
		})
		if err != nil {
			return err
		}

		if os.Getenv("SNYK_TOKEN") == "" {
			return fmt.Errorf("SNYK_TOKEN is not set")
		}

		output, code, err := command.Execute(ctx, logger, "sh", append([]string{"-c", "snyk auth $SNYK_TOKEN"})...)
		if code != 0 {
			return fmt.Errorf("%s", output)
		}

		logger.Infof("auth: %s", output)
		if err != nil {
			return err
		}

		output, _, _ = command.Execute(ctx, logger, "snyk", append([]string{"test", repoPath, "--all-sub-projects", "--json"})...)

		r := SnykResponse{}
		err = json.Unmarshal(output, &r)
		if err != nil {
			return err
		}

		// Group vulnerabilities by their Snyk Reference ID and module name, also filter out license issues
		snykVulnerabilitiesMap := make(map[string]map[string][]SnykVulnerability)
		for _, v := range r.Vulnerabilities {
			if v.Type == "license" {
				continue
			}

			_, ok := snykVulnerabilitiesMap[v.ID]
			if !ok {
				snykVulnerabilitiesMap[v.ID] = make(map[string][]SnykVulnerability)
			}

			snykVulnerabilitiesMap[v.ID][v.ModuleName] = append(snykVulnerabilitiesMap[v.ID][v.ModuleName], v)
		}

		vulns := []report.Vulnerability{}
		// for each pair of (snyk vuln & module name), create a vulcan vuln
		for _, snykModulesMap := range snykVulnerabilitiesMap {
			for moduleName, snykIssues := range snykModulesMap {
				vulcanVulnerability := &report.Vulnerability{}

				vulcanVulnerability.Summary = snykIssues[0].Title + ": " + moduleName
				vulcanVulnerability.Description = extractOverview([]byte(snykIssues[0].Description))
				vulcanVulnerability.Details = createDetails(snykIssues)
				vulcanVulnerability.ImpactDetails = extractImpactDetails([]byte(snykIssues[0].Description))
				vulcanVulnerability.Score = snykIssues[0].CVSSScore
				vulcanVulnerability.Recommendations = extractRecommendations([]byte(snykIssues[0].Description))

				cweCount := len(snykIssues[0].Identifiers.CWE)
				if cweCount > 0 {
					if cweCount > 1 {
						logger.Infof("Multiple CWE found (SNYK ID: %f). Storing the first CWE found.", snykIssues[0].CVSSScore)
					}

					cweID, err := strconv.Atoi(strings.ReplaceAll(snykIssues[0].Identifiers.CWE[0], "CWE-", ""))
					if err != nil {
						logger.Errorf("Not possible to convert %s to uint32", snykIssues[0].Identifiers.CWE[0])
					} else {
						vulcanVulnerability.CWEID = uint32(cweID)
					}
				}

				for _, ref := range snykIssues[0].References {
					vulcanVulnerability.References = append(vulcanVulnerability.References, ref.URL)
				}

				vulns = append(vulns, *vulcanVulnerability)
			}
		}

		state.AddVulnerabilities(vulns...)

		return nil
	}
	c := check.NewCheckFromHandler(checkName, run)

	c.RunAndServe()
}

func createDetails(vulnerabilities []SnykVulnerability) string {
	res := ""
	for _, vulnerability := range vulnerabilities {
		str := "Introduced through: "
		n := len(vulnerability.From)
		for i := 0; i < n; i++ {
			str = str + vulnerability.From[i]
			if i < n-2 {
				str = str + " > "
			}
		}
		res = res + str + "\n"
	}
	return res
}

var regexpRemediationTagBegin = regexp.MustCompile(`(?i)<h2.*id="remediation".*</h2>`)
var regexpRemediationTagEnd = regexp.MustCompile(`(?i)<h2.*>`)
var bluemondayParser = bluemonday.StrictPolicy()

func extractRecommendations(buf []byte) []string {
	markdownParser := parser.NewWithExtensions(parser.CommonExtensions | parser.AutoHeadingIDs)

	res := []string{}

	bufStr := string(buf)
	bufStr = strings.ReplaceAll(bufStr, "\\\\r\\\\n", "\n")
	bufStr = strings.ReplaceAll(bufStr, "\\\\n", "\n")
	bufStr = strings.ReplaceAll(bufStr, "--|", "---|")

	html := markdown.ToHTML([]byte(bufStr), markdownParser, nil)

	locationTagRemediations := regexpRemediationTagBegin.FindIndex(html)
	if len(locationTagRemediations) > 1 {
		remediationSection := html[locationTagRemediations[1]:]

		locationTagRemediationsEnd := regexpRemediationTagEnd.FindIndex(remediationSection)
		if len(locationTagRemediationsEnd) > 1 {
			remediationSection = remediationSection[:locationTagRemediationsEnd[0]]
		}

		remediationStrLines := strings.Split(string(remediationSection), "\n")
		for _, line := range remediationStrLines {
			if len(line) > 0 {
				aux := bluemondayParser.Sanitize(line)
				aux = strings.Trim(aux, "\n")
				if len(aux) > 0 {
					res = append(res, aux)
				}
			}
		}
	}
	return res
}

var regexpOverviewTagBegin = regexp.MustCompile(`(?i)<h2.*id="overview".*</h2>`)

var regexpDetailsTagBegin = regexp.MustCompile(`(?i)<h2.*id="details".*</h2>`)

var regexpNextH2TagBegin = regexp.MustCompile(`(?i)<h2`)

func extractImpactDetails(buf []byte) string {
	markdownParser := parser.NewWithExtensions(parser.CommonExtensions | parser.AutoHeadingIDs)

	bufStr := string(buf)
	bufStr = strings.ReplaceAll(bufStr, "\\\\r\\\\n", "\n")
	bufStr = strings.ReplaceAll(bufStr, "\\\\n", "\n")
	bufStr = strings.ReplaceAll(bufStr, "--|", "---|")

	html := markdown.ToHTML([]byte(bufStr), markdownParser, nil)

	locationTagDetails := regexpDetailsTagBegin.FindIndex(html)
	if len(locationTagDetails) > 1 {
		html = html[locationTagDetails[1]:]
		locationTagNextH2 := regexpNextH2TagBegin.FindIndex(html)
		if len(locationTagNextH2) > 1 {
			html = html[:locationTagNextH2[0]]
		}
		return strings.Trim(string(html), "\n")
	}

	return ""
}

func extractOverview(buf []byte) string {
	markdownParser := parser.NewWithExtensions(parser.CommonExtensions | parser.AutoHeadingIDs)

	bufStr := string(buf)
	bufStr = strings.ReplaceAll(bufStr, "\\\\r\\\\n", "\n")
	bufStr = strings.ReplaceAll(bufStr, "\\\\n", "\n")
	bufStr = strings.ReplaceAll(bufStr, "--|", "---|")

	html := markdown.ToHTML([]byte(bufStr), markdownParser, nil)

	locationTagOverview := regexpOverviewTagBegin.FindIndex(html)
	if len(locationTagOverview) > 1 {
		html = html[locationTagOverview[1]:]
		locationTagNextH2 := regexpNextH2TagBegin.FindIndex(html)
		if len(locationTagNextH2) > 1 {
			html = html[:locationTagNextH2[0]]
		}
		return strings.Trim(string(html), "\n")
	}

	return ""
}
