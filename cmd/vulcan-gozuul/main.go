/*
Copyright 2019 Adevinta
*/

package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	gozuul "github.com/adevinta/gozuul"
	check "github.com/adevinta/vulcan-check-sdk"
	"github.com/adevinta/vulcan-check-sdk/helpers"
	checkstate "github.com/adevinta/vulcan-check-sdk/state"
	report "github.com/adevinta/vulcan-report"
	types "github.com/adevinta/vulcan-types"
)

const (
	checkName = "vulcan-gozuul"
)

var (
	// NOTE: should we increase to critical?
	gozuulVuln = report.Vulnerability{
		CWEID:           434,
		Summary:         "Remote Code Execution in Zuul",
		Description:     "Zuul was configured with zuul.filter.admin.enabled to True, which can be used to upload filters via the default application port which may result in Remote Code Execution (RCE).",
		Score:           report.SeverityThresholdHigh,
		ImpactDetails:   "Allows remote attackers to execute code in the server via uploading a malicious filter.",
		References:      []string{"https://github.com/Netflix/security-bulletins/blob/master/advisories/nflx-2016-003.md"},
		Recommendations: []string{"Ensure the property ZUUL_FILTER_ADMIN_ENABLED is set to False."},
		Labels:          []string{"issue", "http"},
	}

	ErrBadTarget  = errors.New("bad target")
	ErrBadOptions = errors.New("bad options")
)

type options struct {
	Schemes []string `json:"schemes"`
	Ports   []int    `json:"ports"`
}

func main() {
	run := func(ctx context.Context, target, assetType, optJSON string, state checkstate.State) (err error) {
		logger := check.NewCheckLog(checkName)

		var opt options
		if optJSON != "" {
			if err := json.Unmarshal([]byte(optJSON), &opt); err != nil {
				return fmt.Errorf("%w: %v", ErrBadOptions, err)
			}
		}

		isReachable, err := helpers.IsReachable(target, assetType, nil)
		if err != nil {
			logger.Warnf("Can not check asset reachability: %v", err)
		}
		if !isReachable {
			return checkstate.ErrAssetUnreachable
		}

		urls, err := discoverURLs(target, opt.Schemes, opt.Ports)
		if err != nil {
			return err
		}

		for _, url := range urls {
			res, err := gozuul.PassiveScan(url)
			if err != nil {
				return err
			}
			if res.Vulnerable {
				vuln := gozuulVuln
				vuln.AffectedResource = url
				vuln.Fingerprint = helpers.ComputeFingerprint()
				state.AddVulnerabilities(vuln)
			}
		}

		return nil
	}

	c := check.NewCheckFromHandler(checkName, run)
	c.RunAndServe()
}

func discoverURLs(target string, schemes []string, ports []int) ([]string, error) {
	if len(schemes) == 0 {
		schemes = append(schemes, "http", "https")
	}
	if len(ports) == 0 {
		ports = append(ports, 80, 443)
	}

	var urls []string
	switch {
	case types.IsWebAddress(target):
		if testURL(target) {
			urls = append(urls, target)
		}
	case types.IsHostname(target) || types.IsIP(target):
		for _, scheme := range schemes {
			for _, port := range ports {
				url := fmt.Sprintf("%s://%s:%d", scheme, target, port)
				if testURL(url) {
					urls = append(urls, url)
				}
			}
		}
	default:
		return nil, fmt.Errorf("%w: '%s' can not be converted to a URL", ErrBadTarget, target)
	}

	return urls, nil
}

func testURL(url string) bool {
	timeout := 5 * time.Second
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: tr,
		Timeout:   timeout,
	}

	_, err := client.Get(url)

	return err == nil
}
