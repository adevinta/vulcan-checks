/*
Copyright 2021 Adevinta
*/

package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	check "github.com/adevinta/vulcan-check-sdk"
	"github.com/adevinta/vulcan-check-sdk/helpers"
	"github.com/adevinta/vulcan-check-sdk/state"
	checkstate "github.com/adevinta/vulcan-check-sdk/state"
	report "github.com/adevinta/vulcan-report"
	"github.com/sirupsen/logrus"
)

var (
	checkName = "vulcan-exposed-files"
	logger    = check.NewCheckLog(checkName)
)

type FileCheck struct {
	Name  string
	Score float32
	Path  []string // File path to test for
	Grep  []string // File content that must exist in file (to avoid false positives)
}

func main() {
	run := func(ctx context.Context, target, assetType, optJSON string, state checkstate.State) error {
		if target == "" {
			return fmt.Errorf("check target missing")
		}

		isReachable, err := helpers.IsReachable(target, assetType, nil)
		if err != nil {
			logger.Warnf("Can not check asset reachability: %v", err)
		}
		if !isReachable {
			return checkstate.ErrAssetUnreachable
		}

		return scanTarget(ctx, target, logger, state, nil)
	}
	c := check.NewCheckFromHandler(checkName, run)
	c.RunAndServe()

}

func scanTarget(ctx context.Context, target string, logger *logrus.Entry, state state.State, args []string) error {
	httpClient := &http.Client{
		// Set timeout for HTTP request.
		Timeout: time.Duration(10 * time.Second),
		// Do not verify SSL certificate.
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		// Don't follow redirects
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	targets, err := resolveTargets(*httpClient, target)
	if err != nil {
		return err
	}
	if targets == nil {
		// Neither port 80 or 443 is open
		return nil
	}

	checks := []FileCheck{
		{
			"SSH keys",
			report.SeverityThresholdHigh,
			[]string{"/id_rsa", "/id_dsa", "/.ssh/id_rsa", "/.ssh/id_dsa"},
			[]string{"BEGIN PRIVATE KEY", "BEGIN RSA PRIVATE KEY", "BEGIN DSA PRIVATE KEY"},
		},
		{
			"AWS Credentials",
			report.SeverityThresholdHigh,
			[]string{"/.aws/credentials"},
			[]string{"[default]", "aws_access_key_id", "AWS_ACCESS_KEY_ID", "aws_secret_access_key", "AWS_SECRET_ACCESS_KEY"},
		},
		{
			"Shell files",
			report.SeverityThresholdHigh,
			[]string{"/.bash_history", "/.zsh_history", "/.profile", "/.env"},
			[]string{"NODE_ENV=", "APP_ENV=", "_SECRET=", "_PASSWORD=", "access_key", ".secret", "_KEY=", "_ENCRYPTION=", "ENCRYPTION_"},
		},
		{
			"dump.sql", // Default file in most documentations
			report.SeverityThresholdHigh,
			[]string{"/dump.sql"},
			[]string{"INSERT INTO"},
		},
		{
			"Drupal backup files",
			report.SeverityThresholdHigh,
			[]string{"/sites/default/private/files/backup_migrate/scheduled/test.txt"},
			[]string{"this file should not be publicly accessible"},
		},
		{
			"Magento configuration",
			report.SeverityThresholdHigh,
			[]string{"/app/etc/local.xml"},
			[]string{"<config"},
		},
		{
			"Git config",
			report.SeverityThresholdMedium,
			[]string{"/.git/config"},
			[]string{"[core]"},
		},
		{
			"Core dump (ELF) or Spring Boot /dump",
			report.SeverityThresholdMedium,
			[]string{"/dump"},
			[]string{"\x7fELF", "threadName"},
		},
		{
			"Spring Boot environment variables",
			report.SeverityThresholdMedium,
			[]string{"/env", "/actuator/env"},
			[]string{"systemProperties", "systemEnvironment"},
		},
		{
			"PHP info",
			report.SeverityThresholdLow,
			[]string{"/phpinfo.php"},
			[]string{"PHP Version =>"},
		},
		{
			"IntelliJ Configuration",
			report.SeverityThresholdLow,
			[]string{"/.idea/WebServers.xml"},
			[]string{"name=\"WebServers\""},
		},
		{
			".DS_Store file",
			report.SeverityThresholdLow,
			[]string{"/.DS_Store"},
			[]string{"\x00\x00\x00\x01Bud1"}, // Bud1 signature of .DS_Store
		},
	}

	for _, target := range targets {
		logger.Infof("Scan target: %s", target)
		for _, check := range checks {
			for _, path := range check.Path {
				checkUrl := target + path
				logger.Debugf("Testing URL: %s", checkUrl)
				response, err := httpClient.Get(checkUrl)
				if err != nil {
					logger.Fatal(err)
				}

				bodyBytes, err := ioutil.ReadAll(response.Body)
				if err != nil {
					return err
				}
				response.Body.Close()
				if len(bodyBytes) == 0 {
					continue
				}

				for _, grep := range check.Grep {
					if strings.Contains(string(bodyBytes), grep) {
						logger.Debugf("Vulnerability found! Url: %s Match: %s\n", checkUrl, grep)

						vulnReport := report.Vulnerability{
							Summary:         "Sensitive file exposed on web server",
							Score:           check.Score,
							References:      []string{checkUrl},
							Recommendations: []string{"Remove file from webserver.", "Add sensitive files to .gitignore"},
							Description:     "The server stores sensitive information in files or directories that are accessible to actors outside of the intended control sphere.",
							Details:         checkUrl + " is publicly available which contains sensitive information.",
							CWEID:           538, // File and Directory Information Exposure
						}
						state.AddVulnerabilities(vulnReport)
						break
					}
				}
			}

		}
	}
	return nil
}

func resolveTargets(httpClient http.Client, target string) ([]string, error) {
	var possibleTarget string
	var errs []error
	var targets []string
	schemas := []string{"https://", "http://"}

	for _, schema := range schemas {
		possibleTarget = schema + target
		logger.Debugf("Possible target URL: %s", possibleTarget)
		_, err := httpClient.Get(possibleTarget)
		if err != nil {
			errs = append(errs, err)
			logger.WithError(err).WithFields(logrus.Fields{
				"failedPossibleTarget": possibleTarget,
			}).Warn("not a valid target")
			continue
		}
		logger.Debugf("Target URL identified: %s", possibleTarget)
		targets = append(targets, possibleTarget)
	}
	return targets, nil
}
