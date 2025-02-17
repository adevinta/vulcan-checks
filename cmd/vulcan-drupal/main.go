/*
Copyright 2019 Adevinta
*/

package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"time"

	version "github.com/hashicorp/go-version"
	"github.com/sirupsen/logrus"

	check "github.com/adevinta/vulcan-check-sdk"
	"github.com/adevinta/vulcan-check-sdk/helpers"
	checkstate "github.com/adevinta/vulcan-check-sdk/state"
	report "github.com/adevinta/vulcan-report"
)

const checkName = "vulcan-drupal"

var drupalVersion = regexp.MustCompile("Drupal (.+?),")

func detectVulnerabilities(versionString string, u url.URL) ([]report.Vulnerability, error) {
	var vulnerabilities []report.Vulnerability

	ver, err := version.NewVersion(versionString)
	if err != nil {
		return []report.Vulnerability{}, err
	}

	for _, v := range drupalVulnerabilities {
		for _, c := range v.Constraints {
			constraint, err := version.NewConstraint(c)
			if err != nil {
				return []report.Vulnerability{}, err
			}

			if constraint.Check(ver) {
				v.Vulnerability.AffectedResource = u.String()
				v.Vulnerability.Fingerprint = helpers.ComputeFingerprint(ver)
				vulnerabilities = append(vulnerabilities, v.Vulnerability)
			}
		}
	}

	return vulnerabilities, nil
}

func checkVersion(changelogURL string, log *logrus.Entry) (drupal bool, version string, err error) {
	// Set timeout for HTTP request.
	timeout := 10 * time.Second
	// Do not verify SSL certificate.
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		// Do not follow redirect.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: tr,
		Timeout:   timeout,
	}

	req, err := http.NewRequest("GET", changelogURL, nil)
	if err != nil {
		return false, "", err
	}

	log.WithFields(logrus.Fields{
		"url":     changelogURL,
		"request": req,
	}).Debug("making request to target")

	resp, err := client.Do(req)
	if err != nil {
		return false, "", err
	}
	defer resp.Body.Close()

	log.WithFields(logrus.Fields{
		"status_code":      resp.StatusCode,
		"response_headers": resp.Header,
	}).Debug("received response from target")

	if resp.StatusCode != http.StatusOK {
		return false, "", errors.New("CHANGELOG.txt not found")
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, "", err
	}

	matches := drupalVersion.FindStringSubmatch(string(body))

	if len(matches) > 1 {
		return true, matches[1], nil
	}

	return false, "", nil
}

func main() {
	c := check.NewCheckFromHandler(checkName, run)
	c.RunAndServe()
}

func run(ctx context.Context, target, assetType, optJSON string, state checkstate.State) error {
	logger := check.NewCheckLogFromContext(ctx, checkName)

	isReachable, err := helpers.IsReachable(target, assetType, nil)
	if err != nil {
		logger.Warnf("Can not check asset reachability: %v", err)
	}
	if !isReachable {
		return checkstate.ErrAssetUnreachable
	}

	u := url.URL{}
	u.Host = target
	u.Path = "CHANGELOG.txt"

	var drupal bool
	var version string
	for _, scheme := range []string{"http", "https"} {
		u.Scheme = scheme
		drupal, version, err = checkVersion(u.String(), logger)
		if err != nil {
			logger.WithError(err).WithFields(logrus.Fields{
				"url":     u.String(),
				"drupal":  drupal,
				"version": version,
			}).Warn("failed to identify Drupal version")
		}

		logger.WithFields(logrus.Fields{
			"url":     u.String(),
			"drupal":  drupal,
			"version": version,
		}).Info("attempted to identify Drupal version")
		if drupal {
			break
		}
	}

	if drupal {
		infoDrupal.Details = fmt.Sprintf("Drupal %v\nDetected in: %v", version, u.String())
		infoDrupal.AffectedResource = u.String()
		infoDrupal.Fingerprint = helpers.ComputeFingerprint(version)
		state.AddVulnerabilities(infoDrupal)

		vulnerabilities, err := detectVulnerabilities(version, u)
		if err != nil {
			return err
		}

		if len(vulnerabilities) > 0 {
			state.AddVulnerabilities(vulnerabilities...)
		}
	}

	return nil
}
