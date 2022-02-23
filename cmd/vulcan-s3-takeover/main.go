/*
Copyright 2019 Adevinta
*/

package main

import (
	"context"
	"crypto/tls"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	check "github.com/adevinta/vulcan-check-sdk"
	"github.com/adevinta/vulcan-check-sdk/helpers"
	checkstate "github.com/adevinta/vulcan-check-sdk/state"
	report "github.com/adevinta/vulcan-report"
)

const (
	// https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucketnamingrules.html
	bucketNameRegexStr = `BucketName: ([a-z0-9.-]+)`

	noSuchBucket = "NoSuchBucket"
	timeout      = 3 * time.Second
)

var (
	checkName = "vulcan-s3-takeover"
	logger    = check.NewCheckLog(checkName)

	s3Takeover = report.Vulnerability{
		CWEID:   284,
		Summary: "S3 Subdomain Takeover",
		Description: "One of your DNS records points to S3 and there is currently no S3 bucket " +
			"associated to your domain name. This makes it possible for an attacker to create such a bucket " +
			"and take control of the content that is displayed by visiting your domain through HTTP.",
		Score: report.SeverityThresholdHigh,
		ImpactDetails: "An attacker may be able to create a bucket with your domain name so that " +
			"all HTTP requests to your domain will reach the attacker-controlled S3 bucket. " +
			"Potential impact includes phishing/fraud and cookie/account hijacking.",
		References: []string{
			"https://labs.detectify.com/2014/10/21/hostile-subdomain-takeover-using-herokugithubdesk-more/",
		},
		Recommendations: []string{
			"Create the S3 bucket with your domain name",
			"Remove the DNS record pointing to S3",
		},
		Labels: []string{"issue", "aws", "dns"},
	}

	bucketNameRegex *regexp.Regexp
)

type s3Response struct {
	Code       string `xml:"Code"`
	BucketName string `xml:"BucketName"`
}

func main() {
	run := func(ctx context.Context, target, assetType, optJSON string, state checkstate.State) (err error) {
		bucketNameRegex, err = regexp.Compile(bucketNameRegexStr)
		if err != nil {
			return err
		}

		logger := check.NewCheckLog(checkName)

		isReachable, err := helpers.IsReachable(target, assetType, nil)
		if err != nil {
			logger.Warnf("Can not check asset reachability: %v", err)
		}
		if !isReachable {
			return checkstate.ErrAssetUnreachable
		}

		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client := &http.Client{
			Transport: tr,
			Timeout:   timeout,
		}

		for _, website := range resolveTargets(target, assetType) {
			logger.WithFields(logrus.Fields{
				"target":  target,
				"website": website,
			}).Debug("requesting target website")

			resp, err := client.Get(website)
			if err != nil {
				// Don't fail the check if the target can not be accessed.
				return nil
			}
			defer resp.Body.Close()

			logger.WithFields(logrus.Fields{
				"status_code": resp.StatusCode,
				"headers":     resp.Header,
			}).Debug("response recieved")

			if resp.StatusCode == http.StatusNotFound {
				if resp.Header.Get("Server") == "AmazonS3" {
					contentType := resp.Header.Get("Content-Type")
					if strings.HasPrefix(contentType, "application/xml") {
						dec := xml.NewDecoder(resp.Body)
						var s3Resp s3Response
						err := dec.Decode(&s3Resp)
						if err != nil {
							return err
						}

						if s3Resp.Code == noSuchBucket {
							logger.WithFields(logrus.Fields{"bucket_name": s3Resp.BucketName}).Info("Bucket Name found")

							vuln := s3Takeover
							vuln.Details += fmt.Sprintf("URL visited: %s\nContent:\n\n%#v\n", website, s3Resp)
							vuln.AffectedResource = website
							vuln.Fingerprint = helpers.ComputeFingerprint(s3Resp.BucketName)
							state.AddVulnerabilities(vuln)
						}
					} else if strings.HasPrefix(contentType, "text/html") {
						body, err := ioutil.ReadAll(resp.Body)
						if err != nil {
							return err
						}

						if strings.Contains(string(body), noSuchBucket) {
							var bucketName string
							if matches := bucketNameRegex.FindSubmatch(body); len(matches) == 2 {
								bucketName = string(matches[1])
								logger.WithFields(logrus.Fields{"bucket_name": bucketName}).Info("Bucket Name found")
							}

							vuln := s3Takeover
							vuln.Details += fmt.Sprintf("URL visited: %s\nContent:\n\n%s\n", website, body)
							vuln.AffectedResource = website
							vuln.Fingerprint = helpers.ComputeFingerprint(bucketName)
							state.AddVulnerabilities(vuln)
						}
					}
				}
			}
		}

		return nil
	}

	c := check.NewCheckFromHandler(checkName, run)
	c.RunAndServe()
}

func resolveTargets(target, assetType string) (resolved []string) {
	switch assetType {
	case "WebAddress":
		resolved = append(resolved, target)
	case "Hostname":
		resolved = append(resolved, fmt.Sprintf("http://%v/", target), fmt.Sprintf("https://%v/", target))
	}
	return
}
