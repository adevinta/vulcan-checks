package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"
	"golang.org/x/time/rate"
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

	// falsePositiveMessage is the message that will be displayed
	// in the details section if the exposed resources of the check
	// are flagged as false positives.
	falsePositiveMessage = "The check found %v out of %v resources without reliable detection mechanisms. Flagged as false positive."
	// falsePositiveThreshold is the ratio of found resources
	// found with low or medium confidence necessary to consider
	// that the HTTP server is returning false OK statuses and
	// flag the found resources as a false positives.
	falsePositiveThreshold = 0.80
	// falsePositiveMinimum resources is the minimum number of resources
	// with low or medium confidence that the check must be looking
	// for in order for the false positive filtering to take place.
	falsePositiveMinimumResources = 20

	// burst is the maximum number of simultaneous connections to the target.
	burst = 5
	// rateLimit is the maximum rate of simultaneous connections per second.
	rateLimit = 10
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
				Header: []string{"Score", "Severity", "Confidence", "Description", "URL"},
				Rows:   []map[string]string{},
			},
		},
		CWEID: 538, // File and Directory Information Exposure
	}

	logger *logrus.Entry
)

func init() {
	// We don't want to verify certificates in this check.
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
}

func main() {
	run := func(ctx context.Context, target string, optJSON string, state state.State) (err error) {
		logger = check.NewCheckLog(checkName)
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

		vuln, checked := exposedResources(targetURL, resources)

		if vuln == nil {
			return nil
		}

		if len(vuln.Resources) > 0 {
			err = filterFalsePositives(vuln, checked)
			if err != nil {
				return err
			}
		}
		state.AddVulnerabilities(*vuln)

		return nil
	}

	c := check.NewCheckFromHandler(checkName, run)
	c.RunAndServe()
}

func exposedResources(targetURL *url.URL, httpResources []Resource) (*report.Vulnerability, map[string]int) {
	var vuln *report.Vulnerability
	vulnResources := []map[string]string{}
	checkedResources := map[string]int{}

	for _, httpResource := range httpResources {
		checkedResources[rankConfidence(httpResource)]++

		foundResource := checkResource(targetURL, httpResource)
		if foundResource != nil {
			vulnResources = append(vulnResources, foundResource)
		}
	}

	if len(vulnResources) > 0 {
		vuln = &exposedVuln
		vuln.Resources[0].Rows = vulnResources
	}

	return vuln, checkedResources
}

func checkResource(targetURL *url.URL, httpResource Resource) map[string]string {
	foundPathsChan := make(chan string)

	go func() {
		limiter := rate.NewLimiter(rate.Limit(rateLimit), burst)
		var wg sync.WaitGroup
		for _, p := range httpResource.Paths {
			wg.Add(1)
			go func() {
				defer wg.Done()

				err := limiter.Wait(context.Background())
				if err != nil {
					logger.Error(err)
					return
				}

				targetResource, err := url.Parse(targetURL.String())
				if err != nil {
					logger.Error(err)
					return
				}

				targetResource.Path = path.Join(targetResource.Path, p)
				if strings.HasSuffix(p, "/") && !strings.HasSuffix(targetResource.Path, "/") {
					targetResource.Path += "/"
				}

				positive, err := checkPath(targetResource, httpResource)
				if err != nil {
					logger.Error(err)
					return
				}

				if positive {
					foundPathsChan <- targetResource.String()
				}
			}()
		}

		wg.Wait()
		close(foundPathsChan)
	}()

	foundPaths := []string{}
	for foundPath := range foundPathsChan {
		foundPaths = append(foundPaths, foundPath)
	}

	if len(foundPaths) < 1 {
		return nil
	}

	var severityRank string
	if httpResource.Severity != nil {
		if *httpResource.Severity > exposedVuln.Score {
			exposedVuln.Score = *httpResource.Severity
		}
		severityRank = rankSeverity(*httpResource.Severity)
	} else {
		severityRank = rankSeverity(report.SeverityThresholdHigh)
	}

	return map[string]string{
		"Score":       fmt.Sprintf("%.01f", *httpResource.Severity),
		"Severity":    severityRank,
		"Confidence":  rankConfidence(httpResource),
		"Description": httpResource.Description,
		"URL":         strings.Join(foundPaths, "\n"),
	}
}

func checkPath(targetResource *url.URL, httpResource Resource) (bool, error) {
	client := http.DefaultClient
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	resp, err := client.Get(targetResource.String())
	if err != nil {
		logger.Debugf("path not reachable: %s, reason %v", targetResource.String(), err)
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

func filterFalsePositives(vuln *report.Vulnerability, checkedStats map[string]int) error {
	// False positives will only be filtered if a minimum of resources are checked.
	if checkedStats["LOW"]+checkedStats["MEDIUM"] < falsePositiveMinimumResources {
		return nil
	}

	vulnStats := map[string]int{}
	highConfidenceScore := 0.0
	for _, resource := range vuln.Resources[0].Rows {
		confidence := resource["Confidence"]
		score, err := strconv.ParseFloat(resource["Score"], 32)
		if err != nil {
			return err
		}

		if confidence == "HIGH" && score > highConfidenceScore {
			// We store the highest score with high confidence.
			highConfidenceScore = score
		}

		// We count the number of resources found for each confidence type.
		vulnStats[confidence]++
	}

	// We check if the ratio of low or medium confidence matches exceeds the defined threshold.
	if float64(vulnStats["LOW"]+vulnStats["MEDIUM"])/float64(checkedStats["LOW"]+checkedStats["MEDIUM"]) > falsePositiveThreshold {
		vuln.Score = float32(highConfidenceScore)
		vuln.Details = fmt.Sprintf(
			falsePositiveMessage,
			vulnStats["LOW"]+vulnStats["MEDIUM"],
			checkedStats["LOW"]+checkedStats["MEDIUM"],
		)
	}

	return nil
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

func rankConfidence(resource Resource) string {
	switch {
	case resource.Regex != "":
		return "HIGH"
	case resource.Status != nil:
		return "MEDIUM"
	default:
		return "LOW"
	}
}
