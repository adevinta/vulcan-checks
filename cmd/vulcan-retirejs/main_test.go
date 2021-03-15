/*
Copyright 2019 Adevinta
*/

package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/net/html"

	"github.com/adevinta/vulcan-check-sdk"
	"github.com/adevinta/vulcan-check-sdk/state"
	"github.com/adevinta/vulcan-report"
)

func init() {
	os.Mkdir("temp", 0755)
}

func TestRelativePathWithDotSlash(t *testing.T) {
	baseUrl := "http://host.tld/"
	path := "./my/script.js"
	absoluteUrl := getAbsoluteUrl(baseUrl, path)
	if absoluteUrl != baseUrl+"my/script.js" {
		t.Fatalf("Not the correct url: %s", absoluteUrl)
	}
}

func TestRelativePathSlash(t *testing.T) {
	baseUrl := "http://host.tld/"
	path := "/my/script.js"
	absoluteUrl := getAbsoluteUrl(baseUrl, path)
	if absoluteUrl != baseUrl+"my/script.js" {
		t.Fatalf("Not the correct url: %s", absoluteUrl)
	}
}

func TestRelativePathDoubleSlash(t *testing.T) {
	baseUrl := "http://host.tld/"
	path := "//my/script.js"
	absoluteUrl := getAbsoluteUrl(baseUrl, path)
	if absoluteUrl != baseUrl+"my/script.js" {
		t.Fatalf("Not the correct url: %s", absoluteUrl)
	}
}

func TestRelativePathNoSlash(t *testing.T) {
	baseUrl := "http://host.tld/"
	path := "my/script.js"
	absoluteUrl := getAbsoluteUrl(baseUrl, path)
	if absoluteUrl != baseUrl+"my/script.js" {
		t.Fatalf("Not the correct url: %s", absoluteUrl)
	}
}
func TestDownloadFromUrl(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ABCDE"))
	}))
	defer ts.Close()
	downloadFromUrl(ts.URL)
	os.Remove("temp")
}

func TestGetFilePath(t *testing.T) {
	var urlToFilePath = []struct {
		in       string
		expected string
	}{
		{"https://domain.name/scripts/path/jquery.js", "temp/jquery.js"},
		{"https://domain.name/script/a", "temp/a"},
		{"https://domain.name/script/", "temp/uuid"},
		{"https://domain.name/script", "temp/script"},
	}
	for _, tt := range urlToFilePath {
		actual := getFilePath(tt.in)
		if actual != tt.expected && tt.expected != "temp/uuid" {
			t.Fatalf("getFilePath(%s): expected: %s, actual: %s", tt.in, tt.expected, actual)
		}

		if tt.expected == "temp/uuid" && len(actual) != 44 && !strings.HasPrefix(actual, "temp/") {
			t.Fatalf("getFilePath(%s): expected: %s, actual: %s", tt.in, tt.expected, actual)
		}

	}

}

func TestGetScoreCritical(t *testing.T) {
	if getScore("critical") != report.SeverityThresholdCritical {
		t.Fatalf("Critical severity should map to Severity score critical")
	}
}

func TestGetScoreHigh(t *testing.T) {
	if getScore("high") != report.SeverityThresholdHigh {
		t.Fatalf("High severity should map to Severity score high")
	}
}

func TestGetScoreMedium(t *testing.T) {
	if getScore("medium") != report.SeverityThresholdMedium {
		t.Fatalf("medium severity should map to Severity score medium")
	}
}
func TestGetScoreLow(t *testing.T) {
	if getScore("low") != report.SeverityThresholdLow {
		t.Fatalf("low severity should map to Severity score low")
	}
}

func TestGetScoreNone(t *testing.T) {
	if getScore("whatever") != report.SeverityThresholdNone {
		t.Fatalf("severity score none should be the default for non-mapped severity levels")
	}
}

func TestScriptMatcher(t *testing.T) {
	scriptTag := `<script src="localhost">alert(1)</script>`
	scriptNode, err := html.Parse(strings.NewReader(scriptTag))
	if err != nil {
		t.Fatal(err)
	}

	if scriptMatcher(scriptNode.FirstChild.FirstChild.FirstChild) == false {
		t.Fatalf("Valid script tag was not matched")
	}

	linkTag := `<link rel="prefetch" href="localhost/script.js"/>`
	linkNode, err := html.Parse(strings.NewReader(linkTag))
	if err != nil {
		t.Fatal(err)
	}

	if scriptMatcher(linkNode.FirstChild.FirstChild.FirstChild) == false {
		t.Fatalf("Valid link tag was not matched")
	}
}

func TestFindScriptFiles(t *testing.T) {
	localAddr := ""
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(fmt.Sprintf(`<script src="%v/script1.js">alert(1)</script><link rel="prefetch" href="%v/script2.js"/>`, localAddr, localAddr)))
	}))
	defer ts.Close()
	localAddr = ts.URL

	expected := 2
	got := findScriptFiles(localAddr)
	if got != expected {
		t.Fatalf("wrong value for findInlineScripts. Got: %v , expected: %v", got, expected)
	}
}

func TestInlineScripts(t *testing.T) {
	localAddr := ""
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(fmt.Sprintf(`<script>alert(1)</script><link rel="prefetch" href="%v/script2.js"/>`, localAddr)))
	}))
	defer ts.Close()
	localAddr = ts.URL
	expected := 1
	got := findInlineScripts(localAddr)
	if got != expected {
		t.Fatalf("wrong value for findInlineScripts. Got: %v , expected: %v", got, expected)
	}
}

func TestFindTargetHTML(t *testing.T) {
	html := "<html><head></head></html>"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(html))
	}))

	defer ts.Close()
	if getTargetHTML(ts.URL).FirstChild.Data != "html" {
		t.Fatalf("Cannot find target html")
	}
}

func TestIsRelativeUrl(t *testing.T) {
	url := "http://domain.tld/path/to/script"
	if isRelativeUrl(url) {
		t.Fatalf("%s is not a relative url", url)
	}
	relativeUrl := "/path/to/script.js"
	if !isRelativeUrl(relativeUrl) {
		t.Fatalf("%s is a relative url", url)
	}
}

func TestResolveTarget(t *testing.T) {
	redirect := "/landing-page/?n=1"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, _ := strconv.Atoi(r.FormValue("n"))
		if n < 1 {
			http.Redirect(w, r, redirect, http.StatusTemporaryRedirect)
		}
	}))
	defer ts.Close()
	targetResolved, _ := resolveTarget(strings.TrimLeft(ts.URL, "http://"))
	targetExpected := ts.URL + "/landing-page/?n=1"

	if targetResolved != ts.URL+"/landing-page/?n=1" {
		t.Fatalf("resolveTarget did not follow the redirect. Should be %s, was %s", targetExpected, targetResolved)
	}

}

func TestAddVulnsToState(t *testing.T) {
	retireJsVulnerability := RetireJsVulnerability{[]string{"https://bugs.jquery.com/ticket/11974", "http://research.insecurelabs.org/jquery/test/"}, "high", RetireJsResultId{"Issue-123", "Summary text here"}}
	retireJsResult := RetireJsResult{"1.10.2", "jquery", "detection", []RetireJsVulnerability{retireJsVulnerability}}
	retireJsFileResult := RetireJsFileResult{"file", []RetireJsResult{retireJsResult}}
	p := stateMock{}
	r := report.ResultData{
		Error:           "",
		Data:            nil,
		Notes:           "",
		Vulnerabilities: nil,
	}
	state := state.State{ProgressReporter: p, ResultData: &r}
	addVulnsToState(state, []RetireJsFileResult{retireJsFileResult})
	if len(state.Vulnerabilities) != 1 {
		t.Fatalf("We should have exactly one vulnerability")
	}
	if state.Vulnerabilities[0].Score != report.SeverityThresholdHigh {
		t.Fatalf("Score is not mapped correctly, should be %v, but is %v", report.SeverityThresholdHigh, state.Vulnerabilities[0].Score)
	}
}

func TestRunRetireJS(t *testing.T) {
	mockRetireOutput := "{}"

	ctx := context.Background()
	args := []string{"echo", mockRetireOutput}
	_, err := runRetireJs(ctx, args)
	if err != nil {
		t.Fatalf("Error when running runRetireJs: %v", err)
	}
}

func TestScanTarget(t *testing.T) {
	mockRetireOutput := "{}"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	}))
	defer ts.Close()
	u, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatalf("Error when parsing scanTarget: %v", err)
	}

	target := u.Host
	ctx := context.Background()
	args := []string{"echo", mockRetireOutput}

	l := check.NewCheckLog(checkName)
	var state state.State
	err = scanTarget(ctx, target, l, state, args)
	if err != nil {
		t.Fatalf("Error when running scanTarget: %v", err)
	}
}

type stateMock struct{}

func (c stateMock) SetProgress(progress float32) {}
func (c stateMock) Result() (r *report.Report)   { return }
func (c stateMock) Shutdown() (err error)        { return }
