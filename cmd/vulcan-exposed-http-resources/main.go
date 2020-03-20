package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"regexp"
	"strings"

	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"

	check "github.com/adevinta/vulcan-check-sdk"
	"github.com/adevinta/vulcan-check-sdk/state"
	report "github.com/adevinta/vulcan-report"
)

type Resource struct {
	Paths       []string `json:"paths",yaml:"paths"`
	Regex       string   `json:"regex,yaml:"regex",omitempty"`
	Status      *int     `json:"status,yaml:"status",omitempty"`
	Severity    *float32 `json:"severity,yaml:"severity",omitempty"`
	Description string   `json:"description,yaml:"description",omitempty"`
}

type Options struct {
	Resources []Resource `json:"resources",yaml:",inline"`
}

const (
	checkName = "vulcan-exposed-http-resource"
)

var (
	exposedVuln = report.Vulnerability{
		Summary:         "Exposed HTTP Resources",
		Description:     "Private resources are publicly accessible through an HTTP server.",
		ImpactDetails:   "Through the exposed resources, an external attacker may be able to obtain sensitive information (credentials, source code, user data...), interact with sensitive features (content administration, database management...) or have access to additional attack surface.",
		Score:           report.SeverityThresholdHigh,
		Recommendations: []string{"Remove file from web server.", "Forbid access to the reported paths.", "Rotate any leaked credentials."},
		Resources: []report.ResourcesGroup{
			report.ResourcesGroup{
				Name:   "Exposed Resources",
				Header: []string{"URL", "Severity", "Description"},
				Rows:   []map[string]string{},
			},
		},
		CWEID: 538, // File and Directory Information Exposure
	}
)

func init() {
	// We don't want to verify certificates in this check.
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
}

func main() {
	run := func(ctx context.Context, target string, optJSON string, state state.State) (err error) {
		logger := check.NewCheckLog(checkName)
		logger = logger.WithFields(logrus.Fields{"target": target, "options": optJSON})

		targetURL, err := url.Parse(target)
		if err != nil {
			return err
		}

		var opt Options
		if optJSON != "" {
			if err = json.Unmarshal([]byte(optJSON), &opt); err != nil {
				return err
			}
		}

		resources := opt.Resources
		if len(resources) < 1 {
			defaultResourcesFile, err := ioutil.ReadFile("resources.yaml")
			if err != nil {
				return err
			}
			err = yaml.Unmarshal(defaultResourcesFile, &resources)
			if err != nil {
				return err
			}
		}

		vuln, err := exposedResources(logger, targetURL, resources)
		if err != nil {
			return err
		}

		if vuln != nil {
			state.AddVulnerabilities(*vuln)
		}

		return nil
	}

	c := check.NewCheckFromHandler(checkName, run)
	c.RunAndServe()
}

func exposedResources(l *logrus.Entry, targetURL *url.URL, httpResources []Resource) (*report.Vulnerability, error) {
	var vuln *report.Vulnerability
	vulnResources := []map[string]string{}

	for _, httpResource := range httpResources {
		foundResources, err := checkResource(l, targetURL, httpResource)
		if err != nil {
			return nil, err
		}
		if foundResources != nil {
			vulnResources = append(vulnResources, foundResources...)
		}
	}

	if len(vulnResources) > 0 {
		vuln = &exposedVuln
		vuln.Resources[0].Rows = vulnResources
	}

	return vuln, nil
}

func checkResource(l *logrus.Entry, targetURL *url.URL, httpResource Resource) ([]map[string]string, error) {
	foundResources := []map[string]string{}

	for _, p := range httpResource.Paths {
		targetResource, _ := url.Parse(targetURL.String())
		targetResource.Path = path.Join(targetResource.Path, p)
		if strings.HasSuffix(p, "/") && !strings.HasSuffix(targetResource.Path, "/") {
			targetResource.Path += "/"
		}

		positive, err := checkPath(l, targetResource, httpResource)
		if err != nil {
			continue
		}

		if positive {
			var severityRank string
			if httpResource.Severity != nil {
				if *httpResource.Severity > exposedVuln.Score {
					exposedVuln.Score = *httpResource.Severity
				}
				severityRank = rankSeverity(*httpResource.Severity)
			} else {
				severityRank = rankSeverity(report.SeverityThresholdHigh)
			}

			foundResources = append(foundResources, map[string]string{
				"URL":         targetResource.String(),
				"Severity":    severityRank,
				"Description": httpResource.Description,
			})
		}
	}

	return foundResources, nil
}

func checkPath(l *logrus.Entry, targetResource *url.URL, httpResource Resource) (bool, error) {
	client := http.DefaultClient
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	resp, err := client.Get(targetResource.String())
	if err != nil {
		l.Debugf("path not reachable: %s, reason %v", targetResource.String(), err)
		return false, nil
	}
	defer resp.Body.Close() // nolint

	// By default we consider any response to be a positive.
	positive := true

	// If a status is set, only that response status will be a positive.
	if httpResource.Status != nil {
		positive = resp.StatusCode == *httpResource.Status
	}

	// If a regex is set, only a match will be a positive.
	if httpResource.Regex != "" {
		regexPositive, err := checkBodyRegex(resp, httpResource.Regex)
		if err != nil {
			return false, err
		}
		positive = positive && regexPositive
	}

	return positive, nil
}

func checkBodyRegex(resp *http.Response, regex string) (bool, error) {
	contents, err := httputil.DumpResponse(resp, true)
	if err != nil {
		return false, err
	}
	return regexp.Match(regex, contents)
}

func rankSeverity(severity float32) string {
	switch report.RankSeverity(severity) {
	case report.SeverityNone:
		return "NONE"
	case report.SeverityLow:
		return "LOW"
	case report.SeverityMedium:
		return "MEDIUM"
	case report.SeverityHigh:
		return "HIGH"
	case report.SeverityCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}
