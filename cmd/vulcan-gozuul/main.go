package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"time"

	gozuul "github.com/adevinta/gozuul"
	check "github.com/adevinta/vulcan-check-sdk"
	"github.com/adevinta/vulcan-check-sdk/state"
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
		Summary:         "Remote Code Exeucition in Zuul",
		Description:     "Zuul was configured with zuul.filter.admin.enabled to True, which can be used to upload filters via the default application port which may result in Remote Code Execution (RCE).",
		Score:           report.SeverityThresholdHigh,
		ImpactDetails:   "Allows remote attackers to execute code in the server via uploading a malicious filter.",
		References:      []string{"https://github.com/Netflix/security-bulletins/blob/master/advisories/nflx-2016-003.md"},
		Recommendations: []string{"Ensure the property ZUUL_FILTER_ADMIN_ENABLED is set to False."},
	}
)

func main() {
	run := func(ctx context.Context, target string, optJSON string, state state.State) (err error) {
		logger := check.NewCheckLog(checkName)

		target, err = toURL(target)
		if err != nil {
			if errors.Is(err, ErrNotReachable) {
				logger.Info("no HTTP server found in target")
				return nil
			}
			return err
		}

		res, err := gozuul.PassiveScan(target)
		if err != nil {
			return err
		}

		if res.Vulnerable {
			state.AddVulnerabilities(gozuulVuln)
		}

		return nil
	}

	c := check.NewCheckFromHandler(checkName, run)
	c.RunAndServe()
}

var (
	ErrBadTarget    = errors.New("bad target")
	ErrNotReachable = errors.New("not reachable")
)

func toURL(target string) (string, error) {
	switch {
	case types.IsWebAddress(target):
		if testURL(target) {
			return target, nil
		}
	case types.IsHostname(target) || types.IsIP(target):
		for _, scheme := range []string{"https", "http"} {
			url := fmt.Sprintf("%s://%s", scheme, target)
			if testURL(url) {
				return url, nil
			}
		}
	default:
		return "", fmt.Errorf("%w: '%s' can not be converted to a URL", ErrBadTarget, target)
	}

	return "", fmt.Errorf("%w", ErrNotReachable)
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
