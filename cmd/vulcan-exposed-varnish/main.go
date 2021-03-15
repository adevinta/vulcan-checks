/*
Copyright 2019 Adevinta
*/

package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	check "github.com/adevinta/vulcan-check-sdk"
	"github.com/adevinta/vulcan-check-sdk/helpers"
	checkstate "github.com/adevinta/vulcan-check-sdk/state"
	report "github.com/adevinta/vulcan-report"
)

var (
	checkName = "vulcan-exposed-varnish"
	httpPorts = []string{"80", "443", "7001", "7002", "8008", "8080"}

	exposedCache = report.Vulnerability{
		Summary:     "Web Cache Exposed",
		Description: "The asset appears to be a Web Cache, as the X-Cache HTTP header is present in the HTTP response.",
		Score:       report.SeverityThresholdNone,
	}

	exposedVarnish = report.Vulnerability{
		Summary:     "Varnish Cache Exposed",
		Description: "The asset appears to be a Varnish Cache, as the X-Cache header is present and the varnish literal has been found in the response.",
		Score:       report.SeverityThresholdNone,
	}
)

func caseInsensitiveContains(s, substr string) bool {
	s, substr = strings.ToUpper(s), strings.ToUpper(substr)
	return strings.Contains(s, substr)
}

type checker struct {
	client *http.Client
	logger *logrus.Entry
}

func newChecker(l *logrus.Entry) *checker {
	// Set Timeout for HTTP request.
	timeout := 1 * time.Second
	// Do not verify SSL certificate.
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		// Do not follow Redirect.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: tr,
		Timeout:   timeout,
	}

	return &checker{
		client: client,
		logger: l,
	}
}

func (ch *checker) checkWebsite(website string) (cache bool, varnish bool, err error) {
	req, err := http.NewRequest("GET", website, nil)
	if err != nil {
		return false, false, err
	}
	req.Header.Add("Cache-Control", "no-cache")

	ch.logger.WithFields(logrus.Fields{
		"website": website,
		"request": req,
	}).Debug("request target website")

	resp, err := ch.client.Do(req)
	if err != nil {
		// If error making the request, website is not a varnish.
		return false, false, nil
	}

	ch.logger.WithFields(logrus.Fields{
		"status_code":      resp.StatusCode,
		"response_headers": resp.Header,
	}).Debug("request target website")

	for k, v := range resp.Header {
		if k == "X-Cache" {
			cache = true
		}
		if caseInsensitiveContains(k, "varnish") {
			varnish = true
		}

		for _, header := range v {
			if caseInsensitiveContains(header, "varnish") {
				varnish = true
			}
		}
	}

	return cache, varnish, nil
}

func main() {
	c := check.NewCheckFromHandler(checkName, run)
	c.RunAndServe()
}

func run(ctx context.Context, target, assetType, optJSON string, state checkstate.State) error {
	logger := check.NewCheckLog(checkName)

	isReachable, err := helpers.IsReachable(target, assetType, nil)
	if err != nil {
		logger.Warnf("Can not check asset reachability: %v", err)
	}
	if !isReachable {
		return checkstate.ErrAssetUnreachable
	}

	var websites []string
	for _, port := range httpPorts {
		websites = append(websites, fmt.Sprintf("http://%v:%v", target, port))
		websites = append(websites, fmt.Sprintf("https://%v:%v", target, port))
	}

	logger.WithFields(logrus.Fields{
		"target":   target,
		"websites": websites,
	}).Debug("requesting target websites")

	ch := newChecker(logger)

	var addCache, addVarnish bool
	for i, website := range websites {
		cache, varnish, err := ch.checkWebsite(website)
		if err != nil {
			return err
		}

		logger.WithFields(logrus.Fields{
			"website": website,
			"cache":   cache,
			"varnish": varnish,
		}).Debug("response recieved")

		if cache {
			addCache = true
			exposedCache.Details += fmt.Sprintf("* Exposed cache in: %v\n", website)
		}
		if varnish {
			addVarnish = true
			exposedVarnish.Details += fmt.Sprintf("* Exposed varnish in: %v\n", website)
		}

		state.SetProgress(float32((1 + i) / len(websites)))
	}

	if addCache {
		state.AddVulnerabilities(exposedCache)
	}
	if addVarnish {
		state.AddVulnerabilities(exposedVarnish)
	}

	return nil
}
