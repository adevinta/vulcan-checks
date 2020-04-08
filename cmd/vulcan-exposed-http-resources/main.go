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
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

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
	checkName = "vulcan-exposed-http-resources"

	// falsePositiveMinimumRequests is the minimum number of requests
	// the check must do in order for the false positive filtering to take place.
	falsePositiveMinimumRequests = 10
	// falsePositiveOKThreshold is the ratio of 200 OK responses
	// necessary to consider that the HTTP server is consistently returning
	// false OK statuses and flag the found resources as a false positives.
	falsePositiveOKThreshold = 0.80
	// falsePositiveMaximumResources is the maximum number of exposed resources
	// the check is expected to find except for false positives.
	falsePositiveMaximumResources = 20
	// falsePositiveMessage is the message that will be displayed
	// in the details section if the exposed resources of the check
	// are flagged as false positives.
	falsePositiveMessage = "The check found %v exposed resources and %v out of %v requests returned an OK response status. The check considered the web server responses unrealiable and marked low and medium confidence resources as false positives. The highest score among high confidence resources is reported."

	// burst is the maximum number of simultaneous connections to the target.
	burst = 5
	// rateLimit is the maximum rate of connections per second.
	rateLimit = 20
)

var (
	exposedVuln = report.Vulnerability{
		Summary:         "Exposed HTTP Resources",
		Description:     "Private resources are publicly accessible through an HTTP server.",
		ImpactDetails:   "Through the exposed resources, an external attacker may be able to obtain sensitive information (credentials, source code, user data...), interact with sensitive features (content administration, database management...) or have access to additional attack surface.",
		Score:           report.SeverityThresholdNone,
		Recommendations: []string{"Remove the resource from web server.", "Forbid access to the reported paths.", "Rotate any leaked credentials."},
		Resources: []report.ResourcesGroup{
			report.ResourcesGroup{
				Name:   "Exposed Resources",
				Header: []string{"Score", "Severity", "Confidence", "Description", "URL"},
				Rows:   []map[string]string{},
			},
		},
		CWEID: 538, // File and Directory Information Exposure
	}

	responseCount = struct {
		ok    int
		total int
		mutex sync.RWMutex
	}{}

	logger *logrus.Entry
)

func init() {
	// We don't want to verify certificates in this check.
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	// We want to abort connections that are taking too long.
	http.DefaultClient.Timeout = 3 * time.Second
}

func main() {
	run := func(ctx context.Context, target string, optJSON string, state state.State) (err error) {
		logger = check.NewCheckLog(checkName)
		logger = logger.WithFields(logrus.Fields{"target": target, "options": optJSON})

		var opt Options
		if optJSON != "" {
			// TODO: If the options are malformed perhaps we should
			// not return an error but only log it and exit.
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

		targetURL := &url.URL{}
		// Check if the target is already an URL.
		targetURL, err = url.Parse(target)
		// If it is not, try to process it as a hostname.
		if err != nil || (targetURL.Scheme != "http" && targetURL.Scheme != "https") {
			logger.Info("Target does not seem to be a web address.")
			targetURL = &url.URL{Host: target}
			// We check if a web server is exposed on the common schemes.
			for _, scheme := range []string{"https", "http"} {
				logger.Infof("Testing for web server in default %s port.", strings.ToUpper(scheme))
				targetURL.Scheme = scheme
				_, err := http.Get(targetURL.String())
				if err != nil {
					logger.Infof("Server not found in default %s port.", strings.ToUpper(scheme))
					continue
				}

				logger.Infof("Server found in default %s port.", strings.ToUpper(scheme))
				vulnResources := exposedResources(targetURL, resources)
				exposedVuln.Resources[0].Rows = append(exposedVuln.Resources[0].Rows, vulnResources...)
			}
		} else {
			logger.Info("Target seems to be a web address.")
		}

		if len(exposedVuln.Resources[0].Rows) > 0 {
			err = filterFalsePositives(&exposedVuln)
			if err != nil {
				return err
			}

			// Sort rows by severity and then confidence.
			sort.Slice(exposedVuln.Resources[0].Rows, func(i, j int) bool {
				si, err := strconv.ParseFloat(exposedVuln.Resources[0].Rows[i]["Score"], 32)
				if err != nil {
					return false
				}
				sj, err := strconv.ParseFloat(exposedVuln.Resources[0].Rows[j]["Score"], 32)
				if err != nil {
					return true
				}
				switch {
				case si != sj:
					return si > sj
				case exposedVuln.Resources[0].Rows[i]["Confidence"] == "HIGH":
					return true
				case exposedVuln.Resources[0].Rows[i]["Confidence"] == "MEDIUM" &&
					exposedVuln.Resources[0].Rows[j]["Confidence"] == "LOW":
					return true
				default:
					return false
				}
			})

			state.AddVulnerabilities(exposedVuln)
		}

		return nil
	}

	c := check.NewCheckFromHandler(checkName, run)
	c.RunAndServe()
}

func exposedResources(targetURL *url.URL, httpResources []Resource) []map[string]string {
	vulnResources := []map[string]string{}

	logger.WithFields(logrus.Fields{"url": targetURL.String()}).Info("Checking for exposed resources.")
	for _, httpResource := range httpResources {
		foundResources := checkResource(targetURL, httpResource)
		if foundResources != nil {
			vulnResources = append(vulnResources, foundResources...)
		}
	}

	return vulnResources
}

func checkResource(targetURL *url.URL, httpResource Resource) []map[string]string {
	foundPathsChan := make(chan string)

	go func() {
		limiter := rate.NewLimiter(rate.Limit(rateLimit), burst)
		var wg sync.WaitGroup
		for _, p := range httpResource.Paths {
			p := p
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
					logger.WithFields(logrus.Fields{"url": targetResource.String()}).Info("Found exposed resource in URL.")
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

	var foundResources []map[string]string
	for _, path := range foundPaths {
		foundResources = append(foundResources, map[string]string{
			"Score":       fmt.Sprintf("%.01f", *httpResource.Severity),
			"Severity":    severityRank,
			"Confidence":  rankConfidence(httpResource),
			"Description": httpResource.Description,
			"URL":         path,
		})
	}

	return foundResources
}

func checkPath(targetResource *url.URL, httpResource Resource) (bool, error) {
	client := http.DefaultClient
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	resp, err := client.Get(targetResource.String())
	if err != nil && !err.(*url.Error).Timeout() {
		logger.WithFields(logrus.Fields{"path": targetResource.String()}).Debugf("Path not reachable: %v", err)
		return false, nil
	}
	defer resp.Body.Close() // nolint

	positive := false

	// By default we consider any non-nil response to be a positive.
	if resp.StatusCode != 0 {
		positive = true
	}

	// Count response status.
	responseCount.mutex.Lock()
	if resp.StatusCode == http.StatusOK {
		responseCount.ok++
	}
	responseCount.total++
	responseCount.mutex.Unlock()

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

func filterFalsePositives(vuln *report.Vulnerability) error {
	// False positives will only be filtered if a minimum number of requests are made.
	if responseCount.total < falsePositiveMinimumRequests {
		return nil
		logger.WithFields(logrus.Fields{
			"responses_ok":    responseCount.ok,
			"responses_total": responseCount.total,
		}).Infof("False positive detection skipped.")
	}

	// We check for an abnormal rate of OK responses.
	if float32(responseCount.ok)/float32(responseCount.total) > falsePositiveOKThreshold {
		logger.WithFields(logrus.Fields{
			"responses_ok":    responseCount.ok,
			"responses_total": responseCount.total,
		}).Info("False positive threshold met.")
	} else if len(vuln.Resources[0].Rows) > falsePositiveMaximumResources {
		logger.WithFields(logrus.Fields{
			"resources_found":   len(vuln.Resources[0].Rows),
			"resources_maximum": falsePositiveMaximumResources,
		}).Info("False positive found resources maximum met.")
	} else {
		logger.WithFields(logrus.Fields{
			"responses_ok":      responseCount.ok,
			"responses_total":   responseCount.total,
			"resources_found":   len(vuln.Resources[0].Rows),
			"resources_maximum": falsePositiveMaximumResources,
		}).Info("False positive not identified.")
		return nil
	}

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
	}

	vuln.Score = float32(highConfidenceScore)
	vuln.Details = fmt.Sprintf(falsePositiveMessage, len(vuln.Resources[0].Rows), responseCount.ok, responseCount.total)

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
