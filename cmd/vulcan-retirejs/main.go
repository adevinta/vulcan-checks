/*
Copyright 2019 Adevinta
*/

package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	check "github.com/adevinta/vulcan-check-sdk"
	"github.com/adevinta/vulcan-check-sdk/helpers"
	"github.com/adevinta/vulcan-check-sdk/helpers/command"
	checkstate "github.com/adevinta/vulcan-check-sdk/state"
	report "github.com/adevinta/vulcan-report"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
	"github.com/yhat/scrape"
	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

const (
	jsPath = "temp"
)

var (
	checkName  = "vulcan-retirejs"
	logger     = check.NewCheckLog(checkName)
	retireArgs = []string{
		"retire",
		"--exitwith", "0",
		"--js",
		"--outputformat", "json",
		"--jspath", jsPath,
		"--jsrepo", "jsrepository.json",
	}
)

func main() {
	run := func(ctx context.Context, target, assetType, optJSON string, state checkstate.State) error {
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

		return scanTarget(ctx, target, logger, state, nil)
	}
	c := check.NewCheckFromHandler(checkName, run)
	c.RunAndServe()

}

func scanTarget(ctx context.Context, target string, logger *logrus.Entry, state checkstate.State, args []string) error {
	target, err := resolveTarget(target)
	if err != nil {
		// Don't fail the check if the target can not be accessed.
		if _, ok := err.(*url.Error); ok {
			return nil
		}
		return err
	}

	logger.Infof("Downloading javascript sources from %s", target)

	os.RemoveAll(jsPath)
	os.MkdirAll(jsPath, os.ModePerm)
	defer os.RemoveAll(jsPath)

	_, err = findScriptFiles(target)
	if err != nil {
		return err
	}
	_, err = findInlineScripts(target)
	if err != nil {
		return err
	}
	retireJsReport, err := runRetireJs(ctx, args)
	if err != nil {
		return err
	}

	addVulnsToState(state, retireJsReport)

	return nil
}

func runRetireJs(ctx context.Context, args []string) ([]RetireJsFileResult, error) {
	if args == nil || len(args) == 0 {
		args = retireArgs
	}
	var report RetireJsReport
	_, err := command.ExecuteAndParseJSON(ctx, logger, &report, args[0], args[1:]...)

	return report.Data, err
}

func addVulnsToState(state checkstate.State, r []RetireJsFileResult) {
	vulns := make(map[string]report.Vulnerability)
	for _, finding := range r {
		for _, result := range finding.Results {
			for _, vuln := range result.Vulnerabilities {
				summaryText := vuln.Identifiers.Summary
				if vuln.Identifiers.Summary == "" {
					summaryText = "Vulnerabilities in JavaScript Dependencies"
				}

				v, ok := vulns[summaryText]
				if !ok {
					v = report.Vulnerability{
						Summary: summaryText,
						Description: "Vulnerabilities in dependencies may impact in the security of your program. For that reason " +
							"it's important to check for issues not only in your code but in the 3rd party code you are using as a dependency.",
						Score: 0.0,
						Recommendations: []string{
							fmt.Sprintf("Check if there is an update available for the affected components."),
							"Additional vulnerability information can be found in the links in resources",
						},
						Resources: []report.ResourcesGroup{
							report.ResourcesGroup{
								Name: "Vulnerable Components",
								Header: []string{
									"Component",
									"Version",
								},
							},
						},
					}
				}

				if score := getScore(vuln.Severity); v.Score < score {
					v.Score = score
				}

				v.References = append(v.References, vuln.Info...)

				gr := v.Resources[0]
				r := map[string]string{
					"Component": result.Component,
					"Version":   result.Version,
				}
				gr.Rows = append(gr.Rows, r)
				v.Resources[0] = gr

				vulns[summaryText] = v
			}
		}
	}

	for _, v := range vulns {
		state.AddVulnerabilities(v)
	}
}

func getScore(severity string) float32 {
	severity = strings.ToLower(severity)
	if severity == "critical" {
		return report.SeverityThresholdCritical
	}
	if severity == "high" {
		return report.SeverityThresholdHigh
	}
	if severity == "medium" {
		return report.SeverityThresholdMedium
	}
	if severity == "low" {
		return report.SeverityThresholdLow
	}
	return report.SeverityThresholdNone
}

type RetireJsReport struct {
	Data     []RetireJsFileResult          `json:"data"`
	Errors   []map[interface{}]interface{} `json:"errors"`
	Messages []map[interface{}]interface{} `json:"messages"`
	Start    time.Time                     `json:"start"`
	Time     float64                       `json:"time"`
	Version  string                        `json:"version"`
}

type RetireJsFileResult struct {
	File    string           `json:"file"`
	Results []RetireJsResult `json:"results"`
}

type RetireJsResult struct {
	Component       string `json:"component"`
	Detection       string `json:"detection"`
	Version         string `json:"version"`
	Vulnerabilities []RetireJsVulnerability
}

type RetireJsResultId struct {
	Cve     []string `json:"CVE"`
	Bug     string   `json:"bug"`
	Issue   string   `json:"issue"`
	Summary string   `json:"summary"`
}

type RetireJsVulnerability struct {
	AtOrAbove   string           `json:"atOrAbove"`
	Below       string           `json:"below"`
	Identifiers RetireJsResultId `json:"identifiers"`
	Info        []string         `json:"info"`
	Severity    string           `json:"severity"`
}

func findScriptFiles(target string) (int, error) {
	htmlNode, err := getTargetHTML(target)
	if err != nil {
		return 0, err
	}

	count := 0
	for _, tag := range scrape.FindAll(htmlNode, scriptMatcher) {
		url := ""
		if tag.DataAtom == atom.Script {
			url = scrape.Attr(tag, "src")
		}
		if tag.DataAtom == atom.Link {
			url = scrape.Attr(tag, "href")

		}
		if isRelativeUrl(url) {
			url = getAbsoluteUrl(target, url)
		}
		if err := downloadFromUrl(url); err != nil {
			return 0, err
		}
		count++
	}
	return count, nil
}

func getTargetHTML(target string) (*html.Node, error) {
	resp, err := http.Get(target)
	if err != nil {
		return nil, err
	}

	root, err := html.Parse(resp.Body)
	if err != nil {
		return nil, err
	}
	return root, nil
}

func scriptMatcher(n *html.Node) bool {
	if n.DataAtom == atom.Script {
		return len(scrape.Attr(n, "src")) > 0
	}
	if n.DataAtom == atom.Link {
		return scrape.Attr(n, "rel") == "prefetch" && strings.HasSuffix(scrape.Attr(n, "href"), ".js")
	}
	return false
}

func getAbsoluteUrl(targetUrl string, url string) string {
	if strings.HasPrefix(url, "./") {
		url = strings.TrimLeft(url, "./")
	}
	if strings.HasPrefix(url, "//") {
		url = strings.TrimLeft(url, "//")
	}
	if strings.HasPrefix(url, "/") {
		url = strings.TrimLeft(url, "/")
	}
	return targetUrl + url
}

func isRelativeUrl(url string) bool {
	return !strings.Contains(url, "://")
}

// findInlineScripts downloads all inline scripts inside a given target HTML
// it returns the number of dowloaded files
func findInlineScripts(target string) (int, error) {
	inlineMather := func(n *html.Node) bool {
		if n.DataAtom == atom.Script {
			return len(scrape.Attr(n, "src")) <= 0
		}
		return false
	}

	htmlNode, err := getTargetHTML(target)
	if err != nil {
		return 0, err
	}

	count := 0
	for i, inlineScript := range scrape.FindAll(htmlNode, inlineMather) {
		inlineSrc := scrape.Text(inlineScript)
		fileName := fmt.Sprint(jsPath, "/", strconv.Itoa(i), ".js")
		logger.Infof("Writing inline script to file %s", fileName)
		if err := writeFile(fileName, inlineSrc); err != nil {
			return 0, fmt.Errorf("error writing inline script to file: %v", err)
		}
		count++
	}
	return count, nil
}

func writeFile(fileName string, contents string) error {
	file, err := os.Create(fileName)
	if err != nil {
		return err
	}
	_, err = file.WriteString(contents)
	if err != nil {
		return err
	}
	file.Close() // nolint
	return nil
}

func downloadFromUrl(url string) error {
	filePath := getFilePath(url)
	logger.Infof("Downloading %s to %s", url, filePath)
	response, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("error downloading from url %s: %v", url, err)
	}
	defer response.Body.Close()
	bodyBytes, _ := ioutil.ReadAll(response.Body)
	return writeFile(filePath, string(bodyBytes))
}

func getFilePath(url string) string {
	tokens := strings.Split(url, "/")
	fileName := tokens[len(tokens)-1]
	if fileName == "" {
		uuid := uuid.NewV4()
		fileName = uuid.String() + ".js"
	}
	return fmt.Sprint(jsPath, "/", fileName)
}

// Follow redirects and return final URL.
func resolveTarget(target string) (string, error) {
	timeout := 5 * time.Second
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   timeout,
	}

	// TODO: Consider other cases.
	resp, err := client.Get(fmt.Sprintf("https://%s/", target))
	if err == nil {
		return resp.Request.URL.String(), nil
	}

	resp, err = client.Get(fmt.Sprintf("http://%s/", target))
	if err != nil {
		return "", err
	}

	return resp.Request.URL.String(), nil
}
