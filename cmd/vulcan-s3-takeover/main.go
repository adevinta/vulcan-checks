package main

import (
	"context"
	"crypto/tls"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	check "github.com/adevinta/vulcan-check-sdk"
	"github.com/adevinta/vulcan-check-sdk/state"
	report "github.com/adevinta/vulcan-report"
)

const (
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
	}
)

type s3Response struct {
	Code string `xml:"Code"`
}

func main() {
	run := func(ctx context.Context, target, assetType, optJSON string, state state.State) (err error) {
		logger := check.NewCheckLog(checkName)

		// TODO: Also consider case of HTTPS sites.
		website := fmt.Sprintf("http://%v/", target)

		logger.WithFields(logrus.Fields{
			"target":  target,
			"website": website,
		}).Debug("requesting target website")

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

		resp, err := client.Get(website)
		if err != nil {
			// Don't fail the check if the target can not be accessed.
			return nil
		}

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
						state.AddVulnerabilities(s3Takeover)
					}
				} else if strings.HasPrefix(contentType, "text/html") {
					body, err := ioutil.ReadAll(resp.Body)
					if err != nil {
						return err
					}

					if strings.Contains(string(body), noSuchBucket) {
						state.AddVulnerabilities(s3Takeover)
					}
				}
			}
		}
		return nil
	}
	c := check.NewCheckFromHandler(checkName, run)

	c.RunAndServe()
}
