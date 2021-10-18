/*
Copyright 2019 Adevinta
*/

package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/sirupsen/logrus"

	check "github.com/adevinta/vulcan-check-sdk"
	"github.com/adevinta/vulcan-check-sdk/helpers"
	"github.com/adevinta/vulcan-check-sdk/state"
	checkstate "github.com/adevinta/vulcan-check-sdk/state"
	report "github.com/adevinta/vulcan-report"
)

const (
	checkName = "vulcan-http-headers"

	observatoryBin = "httpobs-local-scan"
)

type options struct {
	// Override default ports.
	HTTPPort  string `json:"http-port"`
	HTTPSPort string `json:"https-port"`
}

var behindOktaVuln = report.Vulnerability{
	Summary:     "Okta Authentication",
	Description: "The asset is not reachable because it is behind Okta.",
	Score:       report.SeverityThresholdNone,
	Labels:      []string{"informational", "http"},
}

func main() {
	run := func(ctx context.Context, target, assetType, optJSON string, state checkstate.State) error {
		logger := check.NewCheckLog(checkName)
		e := logger.WithFields(logrus.Fields{"target": target, "options": optJSON})

		if target == "" {
			return errors.New("missing check target")
		}

		isReachable, err := helpers.IsReachable(target, assetType, nil)
		if err != nil {
			logger.Warnf("Can not check asset reachability: %v", err)
		}
		if !isReachable {
			return checkstate.ErrAssetUnreachable
		}

		// TODO: This is maybe too concrete for the check as maybe there are some targets behind other kind of
		// SSO.
		u := hostnameToURL(target)
		if u == nil {
			e.Debug("No HTTP server on target")
			return nil
		}
		behindSSO, redirectingTo, err := helpers.IsRedirectingTo(u.String(), helpers.OKTADomain)
		if err != nil {
			// From go doc: "Any returned error will be of type *url.Error. The
			// url.Error value's Timeout method will report true if request
			// timed out or was canceled."
			// https://golang.org/pkg/net/http/#Client.Do
			e, ok := err.(*url.Error)
			if !ok || !e.Timeout() {
				return err
			}

			return nil
		}
		if behindSSO {
			v := buildBehindOktaVuln(target, redirectingTo)
			state.AddVulnerabilities(v)
			return nil
		}
		var opt options
		if optJSON != "" {
			if err := json.Unmarshal([]byte(optJSON), &opt); err != nil {
				return err
			}
		}
		var scanner observatoryScanner
		checker := check.NewProcessChecker(
			observatoryBin,
			[]string{
				target,
			},
			bufio.ScanLines,
			&scanner,
		)

		if _, err := checker.Run(ctx); err != nil {
			return err
		}

		e.WithFields(logrus.Fields{"raw": string(scanner.output)}).Debug("Raw output scanned")

		var res observatoryResult
		if err := json.Unmarshal(scanner.output, &res); err != nil {
			return err
		}

		e.WithFields(logrus.Fields{"parsed": res}).Debug("Results parsed")

		return processResults(target, res, state)
	}

	c := check.NewCheckFromHandler(checkName, run)
	c.RunAndServe()
}

func buildBehindOktaVuln(target, redirectingTo string) report.Vulnerability {
	behindOktaVuln.AffectedResource = target

	res := report.ResourcesGroup{
		Name: "",
		Header: []string{
			"Target",
			"RedirectingTo",
		},
	}
	res.Rows = []map[string]string{
		map[string]string{
			"Target":        target,
			"RedirectingTo": redirectingTo,
		},
	}
	behindOktaVuln.Resources = append(behindOktaVuln.Resources, res)

	behindOktaVuln.Fingerprint = helpers.ComputeFingerprint(behindOktaVuln.Resources)

	return behindOktaVuln
}

func processResults(target string, r observatoryResult, s state.State) error {
	if r.Error != "" {
		return errors.New(r.Error)
	}

	if err := processCSP(cspVuln, target, r, s); err != nil {
		return err
	}

	processCookies(cookiesVuln, target, r, s)

	processCORS(corsVuln, target, r, s)

	processRedirect(redirectVuln, target, r, s)

	processReferrer(referrerVuln, target, r, s)

	processHSTS(hstsVuln, target, r, s)

	processSRI(sriVuln, target, r, s)

	processXContent(xContentVuln, target, r, s)

	processXFrame(xFrameVuln, target, r, s)

	processXXSS(xXSSVuln, target, r, s)

	processGrading(observatoryGrading, target, r, s)

	return nil
}

func hostnameToURL(hostname string) *url.URL {
	u := url.URL{}
	u.Path = "//"
	u.Host = hostname
	for _, scheme := range []string{"https", "http"} {
		u.Scheme = scheme

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

		_, err := client.Get(u.String())
		if err != nil {
			continue
		}

		return &u
	}

	return nil
}
