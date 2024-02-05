/*
Copyright 2019 Adevinta
*/
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws/awserr"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/support"
	"github.com/sirupsen/logrus"

	check "github.com/adevinta/vulcan-check-sdk"
	"github.com/adevinta/vulcan-check-sdk/helpers"
	checkstate "github.com/adevinta/vulcan-check-sdk/state"
	report "github.com/adevinta/vulcan-report"
	"github.com/aws/aws-sdk-go/aws/arn"
)

const (
	tagRecommendedAction   = `<h4 class='headerBodyStyle'>Recommended Action</h4>`
	tagAdditionalResources = `<h4 class='headerBodyStyle'>Additional Resources</h4>`
)

var (
	checkName = "vulcan-aws-trusted-advisor"
	logger    = check.NewCheckLog(checkName)

	additionalResourcesPattern = regexp.MustCompile(`href=\"(?P<resource>.*?)\"`)
	templateResource           = "$resource"

	rfrshInterval = time.Duration(5 * time.Second)

	// Words to capture for the AffectedResourceString.
	captureWords = []string{
		"Region",
		"Snapshot",
		"Volume",
		"DB Instance",
		"Security Group",
		"Hosted Zone",
		"Record Set",
		"Bucket",
		"Trail",
		"Function",
		"Certificate",
		"Origin",
		"Load Balancer",
		"Access Key",
		"User",
		"Password Policy",
	}
)

type options struct {
	RefreshTimeout int `json:"refresh_timeout"`
}

func main() {
	run := func(ctx context.Context, target, assetType, optJSON string, state checkstate.State) error {
		var opt options
		opt.RefreshTimeout = 5
		if optJSON != "" {
			if err := json.Unmarshal([]byte(optJSON), &opt); err != nil {
				return err
			}
		}
		if target == "" {
			return fmt.Errorf("check target missing")
		}

		return scanAccount(opt, target, assetType, logger, state)
	}
	c := check.NewCheckFromHandler(checkName, run)
	c.RunAndServe()

}

func extractLinesFromHTML(htmlText string) []string {
	result := []string{}

	for _, line := range strings.Split(htmlText, "<br>") {
		line = strings.Replace(line, "\n", "", -1)
		line = strings.Replace(line, "<br>", "", -1)
		line = strings.Replace(line, "<br/>", "", -1)
		line = strings.Replace(line, "</br>", "", -1)
		if len(line) > 0 {
			result = append(result, line)
		}
	}
	return result
}

func scanAccount(opt options, target, assetType string, logger *logrus.Entry, state checkstate.State) error {
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String("us-east-1"),
	})
	if err != nil {
		return err
	}

	assumeRoleEndpoint := os.Getenv("VULCAN_ASSUME_ROLE_ENDPOINT")
	role := os.Getenv("ROLE_NAME")

	isReachable, err := helpers.IsReachable(target, assetType,
		helpers.NewAWSCreds(assumeRoleEndpoint, role))
	if err != nil {
		logger.Warnf("Can not check asset reachability: %v", err)
	}
	if !isReachable {
		return checkstate.ErrAssetUnreachable
	}

	parsedARN, err := arn.Parse(target)
	if err != nil {
		return err
	}
	creds, err := getCredentials(assumeRoleEndpoint, parsedARN.AccountID, role, logger)
	if err != nil {
		return err
	}

	s := support.New(sess, &aws.Config{Credentials: creds})

	// Retrieve checks list
	checks, err := s.DescribeTrustedAdvisorChecks(
		&support.DescribeTrustedAdvisorChecksInput{
			Language: aws.String("en"),
		})
	if err != nil {
		return err
	}

	// Refresh checks
	checkIds := []*string{}
	enqueued := 0
	for _, check := range checks.Checks {
		// Ignore results if we can't know the category
		if check.Category == nil {
			continue
		}

		// Ignore results that does are not security
		if *check.Category != "security" {
			continue
		}
		checkIds = append(checkIds, check.Id)
		refreshed, err := s.RefreshTrustedAdvisorCheck(&support.RefreshTrustedAdvisorCheckInput{CheckId: check.Id})
		if err != nil {
			if awsErr, ok := err.(awserr.Error); ok {
				if awsErr.Code() == "InvalidParameterValueException" {
					logger.Printf("check '%s' is not refreshable\n", *check.Name)
					continue
				}
			}
			return err
		}
		logger.Printf("check '%s' is refreshed with status: '%s'\n", *check.Name, *refreshed.Status.Status)
		if *refreshed.Status.Status == "enqueued" {
			enqueued++
		}
	}

	// If some check was enqueued for refreshing
	// poll it's status and wait up until opt.RefreshTimeout
	if enqueued > 0 {
		t := time.NewTicker(time.Duration(opt.RefreshTimeout) * time.Second)
		defer t.Stop()

	LOOP:
		for {
			select {
			case <-t.C:
				break LOOP
			default:
				checkStatus, err := s.DescribeTrustedAdvisorCheckRefreshStatuses(
					&support.DescribeTrustedAdvisorCheckRefreshStatusesInput{
						CheckIds: checkIds,
					},
				)
				if err != nil {
					if awsErr, ok := err.(awserr.Error); ok {
						if awsErr.Code() != "InvalidParameterValueException" {
							return err
						}
					}
				}
				var pending bool
				for _, cs := range checkStatus.Statuses {
					if *cs.Status == "enqueued" || *cs.Status == "processing" {
						pending = true
						break
					}
				}
				if !pending {
					break LOOP
				}
				logger.Infof("Waiting for checks to be refreshed. Sleeping for %v...", rfrshInterval)
				time.Sleep(rfrshInterval)
			}
		}
	}

	// Retrieve checks summaries
	var alias *string
	captureWordsRegexp, err := regexp.Compile(strings.Join(captureWords, "|"))
	if err != nil {
		return err
	}

	for _, v := range checks.Checks {
		// Ignore results if we can't know the category
		if v.Category == nil {
			continue
		}

		// Ignore results that does are not security
		if *v.Category != "security" {
			continue
		}

		// Ignore results if we can't know the ID
		if v.Id == nil {
			continue
		}

		var checkSummaries *support.DescribeTrustedAdvisorCheckSummariesOutput
		checkSummaries, err = s.DescribeTrustedAdvisorCheckSummaries(
			&support.DescribeTrustedAdvisorCheckSummariesInput{
				CheckIds: []*string{v.Id}})
		if err != nil {
			return err
		}

		for _, summary := range checkSummaries.Summaries {
			// Only process summaries that has flagged resources
			if summary.HasFlaggedResources == nil {
				continue
			}

			if summary.HasFlaggedResources != nil && !*summary.HasFlaggedResources {
				continue
			}

			action := ""
			recommendedActions := []string{}
			additionalResources := []string{}

			// Avoid nil pointer dereference when reading *v.Description
			// description, recommendedActions and additionalResources will be
			// considered empty.
			if v.Description != nil {
				iRecommendedAction := strings.Index(*v.Description, tagRecommendedAction)
				iAdditionalResources := strings.Index(*v.Description, tagAdditionalResources)
				if len(*v.Description) >= iRecommendedAction {
					action = (*v.Description)[:iRecommendedAction]
				}

				// Extract recommendedActions
				if iAdditionalResources >= iRecommendedAction+len(tagRecommendedAction) {
					recommendedActions = extractLinesFromHTML(string(*v.Description)[iRecommendedAction+len(tagRecommendedAction) : iAdditionalResources])

					// Extract additionalResources
					additionalResourcesText := string(*v.Description)[iAdditionalResources+len(tagAdditionalResources):]
					for _, submatches := range additionalResourcesPattern.FindAllStringSubmatchIndex(additionalResourcesText, -1) {
						r := []byte{}
						r = additionalResourcesPattern.ExpandString(r, templateResource, additionalResourcesText, submatches)
						additionalResources = append(additionalResources, string(r))
					}
				} else {
					recommendedActions = extractLinesFromHTML(string(*v.Description)[iRecommendedAction+len(tagRecommendedAction):])
				}
			}

			var checkResults *support.DescribeTrustedAdvisorCheckResultOutput
			checkResults, err = s.DescribeTrustedAdvisorCheckResult(&support.DescribeTrustedAdvisorCheckResultInput{CheckId: v.Id})
			if err != nil {
				return err
			}

			for _, fr := range checkResults.Result.FlaggedResources {
				// Unable to retrieve flagged resource information
				if fr == nil {
					logger.Warnf("result with CheckID: %s does not contain flagged resource information", *checkResults.Result.CheckId)
					continue
				}
				// PTVUL-860
				// Ignore resources that have been marked as supressed/excluded
				if *fr.IsSuppressed {
					logger.Debugf("resource with ResourceID: %s have been marked as excluded", *fr.ResourceId)
					continue
				}
				// Get the alias of the account only if we did not get previously.
				if alias == nil {
					res, err := accountAlias(creds)
					if err != nil {
						return err
					}
					alias = &res
				}

				// Alias can not be nil because the protection before.
				row := map[string]string{"Account": *alias}
				header := []string{"Account"}
				affectedResourceStr := ""
				score := float32(0.0)
				for i := 0; i < len(v.Metadata); i++ {
					fieldName := ""
					if v.Metadata[i] != nil {
						fieldName = *v.Metadata[i]
					}
					value := ""
					if fr.Metadata[i] != nil {
						value = *fr.Metadata[i]
					}

					if fieldName == "Status" {
						score = severityMap[*v.Id][value]
						continue
					}

					if v.Metadata[i] != nil && fr.Metadata[i] != nil {
						row[fieldName] = value
						header = append(header, fieldName)

						// We are capturing just a reduced set of the metadata
						// attributes to be used in the AffectedResourceString
						// field. Mostly those that by their name seem to
						// describe where the actual problem being raised lays.
						if captureWordsRegexp.MatchString(fieldName) {
							affectedResourceStr = fmt.Sprintf("%s%s: %s | ", affectedResourceStr, strings.ReplaceAll(fieldName, " ", ""), value)
						}
					}
				}
				affectedResourceStr = strings.TrimSuffix(affectedResourceStr, " | ")

				occurrences := report.ResourcesGroup{
					Name: "Occurrences",
				}
				occurrences.Rows = append(occurrences.Rows, row)
				occurrences.Header = header

				summary := ""
				// Avoid nil pointer dereference when reading *v.Name
				if v.Name != nil {
					summary = "AWS " + *v.Name
				}

				vuln := report.Vulnerability{
					Summary:     summary,
					Description: action,
					Score:       score,
					// AWS Trusted Advisor provides already an ID generated by
					// them, that seems the best option to indicate which is
					// the affected resource of the finding. However, that
					// field is not very friendly to be shown in the UI, and
					// therefore we are using a set of the metadata values
					// provided by their checks in the AffectedResourceString
					// attribute.
					AffectedResource:       aws.StringValue(fr.ResourceId),
					AffectedResourceString: affectedResourceStr,
					Labels:                 []string{"issue", "aws"},
					Resources:              []report.ResourcesGroup{occurrences},
				}
				vuln.Recommendations = append(vuln.Recommendations, recommendedActions...)
				vuln.References = append(vuln.References, additionalResources...)

				// Doesn't seem to be any useful field to feed the fingerprint
				// of the finding.
				vuln.Fingerprint = helpers.ComputeFingerprint()

				state.AddVulnerabilities(vuln)
			}
		}
	}
	return err
}

// AssumeRoleResponse represent a response from vulcan-assume-role
type AssumeRoleResponse struct {
	AccessKey       string `json:"access_key"`
	SecretAccessKey string `json:"secret_access_key"`
	SessionToken    string `json:"session_token"`
}

func getCredentials(url string, accountID, role string, logger *logrus.Entry) (*credentials.Credentials, error) {
	m := map[string]string{"account_id": accountID}
	if role != "" {
		m["role"] = role
	}
	jsonBody, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal assume role request body for account %s: %w", accountID, err)
	}
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("unable to create request for the assume role service: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		logger.Errorf("cannot do request: %s", err.Error())
		return nil, err
	}
	defer resp.Body.Close() // nolint

	assumeRoleResponse := AssumeRoleResponse{}
	buf, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Errorf("can not read request body %s", err.Error())
		return nil, err
	}

	err = json.Unmarshal(buf, &assumeRoleResponse)
	if err != nil {
		logger.Errorf("Cannot decode request %s", err.Error())
		logger.Errorf("RequestBody: %s", string(buf))
		return nil, err
	}

	return credentials.NewStaticCredentials(
		assumeRoleResponse.AccessKey,
		assumeRoleResponse.SecretAccessKey,
		assumeRoleResponse.SessionToken), nil
}

// accountAlias gets one of the current aliases of the account that the
// credentials passed belong to.
func accountAlias(creds *credentials.Credentials) (string, error) {
	session, err := session.NewSession((&aws.Config{Credentials: creds}))
	if err != nil {
		return "", fmt.Errorf("unable to create a session %w", err)
	}
	svc := iam.New(session)
	resp, err := svc.ListAccountAliases(&iam.ListAccountAliasesInput{})
	if err != nil {
		return "", err
	}
	if len(resp.AccountAliases) == 0 {
		// No aliases found for the aws account.
		return "", nil
	}
	a := resp.AccountAliases[0]
	if a == nil {
		return "", errors.New("unexpected nil getting aliases for aws account")
	}
	return *a, nil
}
