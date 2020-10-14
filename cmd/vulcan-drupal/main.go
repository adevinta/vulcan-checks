package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"time"

	version "github.com/hashicorp/go-version"
	"github.com/sirupsen/logrus"

	check "github.com/adevinta/vulcan-check-sdk"
	checkstate "github.com/adevinta/vulcan-check-sdk/state"
	report "github.com/adevinta/vulcan-report"
)

var (
	checkName     = "vulcan-drupal"
	drupalVersion = regexp.MustCompile("Drupal (.+?),")
)

func detectVulnerabilities(versionString string) ([]report.Vulnerability, error) {
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
		err = fmt.Errorf("%w: %s", checkstate.ErrAssetUnreachable, err.Error())
		return false, "", err
	}
	defer resp.Body.Close()

	log.WithFields(logrus.Fields{
		"status_code":      resp.StatusCode,
		"response_headers": resp.Header,
	}).Debug("recieved response from target")

	if resp.StatusCode != http.StatusOK {
		return false, "", errors.New("CHANGELOG.txt not found")
	}

	body, err := ioutil.ReadAll(resp.Body)
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

func run(ctx context.Context, target string, optJSON string, state checkstate.State) error {
	logger := check.NewCheckLog(checkName)

	u := url.URL{}
	u.Host = target
	u.Path = "CHANGELOG.txt"

	var drupal bool
	var version string
	var err error

	// Check for drupal and its version
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

	if !drupal {
		// If we were not able to check for drupal due to
		// 'No route to host', return ErrAssetUnreachable.
		// Otherwise don't return error.
		if errors.Is(err, checkstate.ErrAssetUnreachable) {
			return err
		}
		return nil
	}

	// Scan drupal
	infoDrupal.Details = fmt.Sprintf("Drupal %v\nDetected in: %v", version, u.String())
	state.AddVulnerabilities(infoDrupal)

	vulnerabilities, err := detectVulnerabilities(version)
	if err != nil {
		return err
	}

	if len(vulnerabilities) > 0 {
		state.AddVulnerabilities(vulnerabilities...)
	}

	return nil
}
