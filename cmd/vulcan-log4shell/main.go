/*
Copyright 2020 Adevinta
*/

package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	check "github.com/adevinta/vulcan-check-sdk"
	"github.com/adevinta/vulcan-check-sdk/helpers"
	"github.com/adevinta/vulcan-check-sdk/helpers/command"
	checkstate "github.com/adevinta/vulcan-check-sdk/state"
	"github.com/adevinta/vulcan-checks/cmd/vulcan-log4shell/scraper"
	report "github.com/adevinta/vulcan-report"
)

type Options struct {
	ScrapDepth int `json:"scrap_depth"`
}

const (
	checkName = "vulcan-log4shell"
	// Default scrap depth.
	defaultScrapDepth = 3
)

var log4jShellVuln = report.Vulnerability{
	Summary:         "Exposed URLs",
	CWEID:           502,
	Description:     "Log4Shell CVE-2021-44228",
	ImpactDetails:   `Remote code execution when logging user controlled input.`,
	Score:           report.SeverityThresholdCritical,
	Recommendations: []string{"Upgrade to the last version of Log4j 2"},
}

func init() {
	// We don't want to verify certificates in this check.
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	// We want to abort connections that are taking too long.
	http.DefaultClient.Timeout = 3 * time.Second
}

func main() {
	run := func(ctx context.Context, target, assetType, optJSON string, state checkstate.State) (err error) {
		logger := check.NewCheckLog(checkName)
		logger = logger.WithFields(logrus.Fields{"target": target, "assetType": assetType, "options": optJSON})

		var opt Options
		if optJSON != "" {
			if err = json.Unmarshal([]byte(optJSON), &opt); err != nil {
				return err
			}
		}
		depth := defaultScrapDepth
		if opt.ScrapDepth != 0 {
			depth = opt.ScrapDepth
		}
		isReachable, err := helpers.IsReachable(target, assetType, nil)
		if err != nil {
			logger.Warnf("Can not check asset reachability: %v", err)
		}
		if !isReachable {
			return checkstate.ErrAssetUnreachable
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
			}
		} else {
			logger.Info("Target seems to be a web address.")
			_, err := http.Get(targetURL.String())
			if err != nil {
				logger.Infof("Server not found in target web address.")
				return nil
			}
		}

		res, err := scraper.Scrap(targetURL, uint(depth))
		if err != nil {
			return err
		}

		var vulns []report.Vulnerability
		for _, url := range res {
			isVuln, err := runLog4jScan(ctx, logger, url)
			if err != nil {
				return err
			}
			if isVuln == "" {
				continue
			}
			l4shellV := log4jShellVuln
			l4shellV.AffectedResource = url
			vulns = append(vulns, l4shellV)
		}
		if len(vulns) > 0 {
			state.AddVulnerabilities(vulns...)
		}
		return nil
	}
	c := check.NewCheckFromHandler(checkName, run)
	c.RunAndServe()
}

func runLog4jScan(ctx context.Context, logger *logrus.Entry, url string) (string, error) {
	vulnerable := []string{}
	bin := "python"
	params := []string{"log4j-scan.py", "--json", "--url", url}
	output, _, err := command.Execute(ctx, logger, bin, params...)
	if err != nil {
		return "", err
	}
	if len(output) == 0 {
		return "", nil
	}
	err = json.Unmarshal(output, &vulnerable)
	if err != nil {
		return "", err
	}
	if len(vulnerable) > 0 {
		return vulnerable[0], nil
	}
	return "", err
}
