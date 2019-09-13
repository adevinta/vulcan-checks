package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws/awserr"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/support"
	"github.com/sirupsen/logrus"

	"github.com/adevinta/vulcan-check-sdk"
	"github.com/adevinta/vulcan-check-sdk/state"
	"github.com/adevinta/vulcan-report"
	"github.com/aws/aws-sdk-go/aws/arn"
)

const (
	tagRecommendedAction   = `<b>Recommended Action</b>`
	tagAdditionalResources = `<b>Additional Resources</b>`
)

var (
	checkName = "vulcan-aws-trusted-advisor"
	logger    = check.NewCheckLog(checkName)

	additionalResourcesPattern = regexp.MustCompile(`href=\"(?P<resource>.*?)\"`)
	templateResource           = "$resource"
)

type options struct {
	VulcanAssumeRoleURL string `json:"vulcan_assume_role_url"`
	Role                string `json:"role"`
	RefreshTimeout      int    `json:"refresh_timeout"`
}

func main() {
	run := func(ctx context.Context, target string, optJSON string, state state.State) error {
		var opt options
		opt.RefreshTimeout = 5
		if optJSON != "" {
			opt.VulcanAssumeRoleURL = "http://localhost:8080/assume"
			if err := json.Unmarshal([]byte(optJSON), &opt); err != nil {
				return err
			}
		}
		if target == "" {
			return fmt.Errorf("check target missing")
		}

		parsedARN, err := arn.Parse(target)
		if err != nil {
			return err
		}

		return scanAccount(opt, parsedARN.AccountID, logger, state)
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

func scanAccount(opt options, target string, logger *logrus.Entry, state state.State) error {
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String("us-east-1"),
	})
	if err != nil {
		return err
	}

	creds, err := getCredentials(opt.VulcanAssumeRoleURL, target, opt.Role, logger)
	if err != nil {
		return err
	}

	s := support.New(sess, &aws.Config{Credentials: creds})

	checks, err := s.DescribeTrustedAdvisorChecks(
		&support.DescribeTrustedAdvisorChecksInput{
			Language: aws.String("en"),
		})
	if err != nil {
		return err
	}

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
	// Let's chill a bit before getting results
	if enqueued > 0 {
		logger.Infof("waiting for checks to be refreshed. Sleeping for %d seconds ...", opt.RefreshTimeout)
		time.Sleep(time.Duration(opt.RefreshTimeout) * time.Second)
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

		resourcesRed := report.ResourcesGroup{
			Name: "Level: Red",
		}

		resourcesYellow := report.ResourcesGroup{
			Name: "Level: Yellow",
		}

		for _, summary := range checkSummaries.Summaries {
			// Only process summaries that has flagged resources
			if summary.HasFlaggedResources == nil {
				continue
			}

			if summary.HasFlaggedResources != nil && *summary.HasFlaggedResources == false {
				continue
			}

			description := ""
			recommendedActions := []string{}
			additionalResources := []string{}

			// Avoid nil pointer dereference when reading *v.Description
			// description, recommendedActions and additionalResources will be
			// considered as empty
			if v.Description != nil {
				iRecommendedAction := strings.Index(*v.Description, tagRecommendedAction)
				iAdditionalResources := strings.Index(*v.Description, tagAdditionalResources)
				description = string(*v.Description)[:iRecommendedAction]

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

				header := []string{}
				row := make(map[string]string)
				for i := 0; i < len(v.Metadata); i++ {

					// TODO drop column STATUS
					fieldName := ""
					if v.Metadata[i] != nil {
						fieldName = *v.Metadata[i]
					}
					value := ""
					if fr.Metadata[i] != nil {
						value = *fr.Metadata[i]
					}

					if v.Metadata[i] != nil && fr.Metadata[i] != nil {
						row[fieldName] = value
						header = append(header, fieldName)
					}
				}

				if row["Status"] == "Yellow" {
					resourcesYellow.Rows = append(resourcesYellow.Rows, row)
					resourcesYellow.Header = header
				}

				if row["Status"] == "Red" {
					resourcesRed.Rows = append(resourcesRed.Rows, row)
					resourcesRed.Header = header
				}
			}

			score := float32(0.0)

			// Avoid nil pointer dereference when reading *v.Id
			// Score will be zeroed
			if v.Id != nil {
				if len(resourcesYellow.Rows) > 0 {
					score = severityMap[*v.Id]["yellow"]
				}
				if len(resourcesRed.Rows) > 0 {
					score = severityMap[*v.Id]["red"]
				}
			}

			if len(resourcesRed.Rows) > 0 || len(resourcesYellow.Rows) > 0 {
				summary := ""
				// Avoid nil pointer dereference when reading *v.Name
				if v.Name != nil {
					summary = "AWS " + *v.Name
				}

				v := report.Vulnerability{
					Summary:     summary,
					Description: description,
					Score:       score,
				}

				for _, r := range recommendedActions {
					v.Recommendations = append(v.Recommendations, r)
				}

				for _, ar := range additionalResources {
					v.References = append(v.References, ar)
				}

				if len(resourcesRed.Rows) > 0 {
					v.Resources = append(v.Resources, resourcesRed)
				}

				if len(resourcesYellow.Rows) > 0 {
					v.Resources = append(v.Resources, resourcesYellow)
				}

				state.AddVulnerabilities(v)
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
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		logger.Errorf("cannot do request: %s", err.Error())
		return nil, err
	}
	defer resp.Body.Close()

	assumeRoleResponse := AssumeRoleResponse{}
	buf, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		logger.Errorf("Cannot read request body %s", err.Error())
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
