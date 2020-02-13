package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	check "github.com/adevinta/vulcan-check-sdk"
	"github.com/adevinta/vulcan-check-sdk/helpers/command"
	"github.com/adevinta/vulcan-check-sdk/state"
	report "github.com/adevinta/vulcan-report"
	uuid "github.com/satori/go.uuid"
	"github.com/sirupsen/logrus"
	"github.com/yhat/scrape"
	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

var (
	checkName  = "vulcan-retirejs"
	logger     = check.NewCheckLog(checkName)
	retireArgs = []string{"retire", "--outputformat", "json", "--jsrepo", "jsrepository.json"}
)

func main() {
	run := func(ctx context.Context, target string, optJSON string, state state.State) error {
		if target == "" {
			return fmt.Errorf("check target missing")
		}
		return scanTarget(ctx, target, logger, state, nil)
	}
	c := check.NewCheckFromHandler(checkName, run)
	c.RunAndServe()

}

func scanTarget(ctx context.Context, target string, logger *logrus.Entry, state state.State, args []string) error {
	target, err := resolveTarget(target)
	if err != nil {
		// Don't fail the check if the target can not be accessed.
		if _, ok := err.(*url.Error); ok {
			return nil
		}
		return err
	}
	logger.Infof("Downloading javascript sources from %s", target)
	os.RemoveAll("./temp")
	os.MkdirAll("temp", os.ModePerm)
	findScriptFiles(target)
	findInlineScripts(target)
	retireJsReport, err := runRetireJs(ctx, args)
	if err != nil {
		return err
	}
	addVulnsToState(state, retireJsReport)
	os.RemoveAll("./temp")
	return nil
}

func runRetireJs(ctx context.Context, args []string) ([]RetireJsFileResult, error) {
	if args == nil || len(args) == 0 {
		args = retireArgs
	}
	var report RetireJsReport
	noFindings, findings, _, err := command.ExecuteWithStdErr(ctx, logger, args[0], args[1:]...)
	if err != nil {
		return report.Data, err
	}

	if len(findings) > 0 {
		err = json.Unmarshal(findings, &report)
	} else {
		err = json.Unmarshal(noFindings, &report)
	}
	return report.Data, err
}

func addVulnsToState(state state.State, r []RetireJsFileResult) {
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
	Version string               `json:"version"`
	Start   time.Time            `json:"start"`
	Data    []RetireJsFileResult `json:"data"`
	Time    float64              `json:"time"`
}

type RetireJsFileResult struct {
	File    string           `json:"file"`
	Results []RetireJsResult `json:"results"`
}

type RetireJsResult struct {
	Version         string `json:"version"`
	Component       string `json:"component"`
	Detection       string `json:"detection"`
	Vulnerabilities []RetireJsVulnerability
}

type RetireJsResultId struct {
	Issue   string `json:"issue"`
	Summary string `json:"summary"`
}

type RetireJsVulnerability struct {
	Info        []string         `json:"info"`
	Severity    string           `json:"severity"`
	Identifiers RetireJsResultId `json:"identifiers"`
}

func findScriptFiles(target string) int {
	count := 0
	for _, tag := range scrape.FindAll(getTargetHTML(target), scriptMatcher) {
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
		downloadFromUrl(url)
		count++
	}
	return count
}

func getTargetHTML(target string) *html.Node {
	resp, err := http.Get(target)
	if err != nil {
		panic(err)
	}

	root, err := html.Parse(resp.Body)
	if err != nil {
		panic(err)
	}
	return root
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
func findInlineScripts(target string) int {
	inlineMather := func(n *html.Node) bool {
		if n.DataAtom == atom.Script {
			return len(scrape.Attr(n, "src")) <= 0
		}
		return false
	}

	count := 0
	for i, inlineScript := range scrape.FindAll(getTargetHTML(target), inlineMather) {
		inlineSrc := scrape.Text(inlineScript)
		fileName := "temp/" + strconv.Itoa(i) + ".js"
		logger.Infof("Writing inline script to file %s", fileName)
		writeFile(fileName, inlineSrc)
		count++
	}
	return count
}

func writeFile(fileName string, contents string) {
	file, err := os.Create(fileName)
	if err != nil {
		logger.Fatal(err)
	}
	_, err = file.WriteString(contents)
	if err != nil {
		logger.Fatal(err)
	}
	file.Close()
}

func downloadFromUrl(url string) {
	filePath := getFilePath(url)
	logger.Infof("Downloading %s to %s", url, filePath)
	response, err := http.Get(url)
	if err != nil {
		logger.Fatal(err)
	}
	defer response.Body.Close()
	bodyBytes, _ := ioutil.ReadAll(response.Body)
	writeFile(filePath, string(bodyBytes))
}

func getFilePath(url string) string {
	tokens := strings.Split(url, "/")
	fileName := tokens[len(tokens)-1]
	if fileName == "" {
		uuid := uuid.NewV4()
		fileName = uuid.String() + ".js"
	}
	return "temp/" + fileName
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
