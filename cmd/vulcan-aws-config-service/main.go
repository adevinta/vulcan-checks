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
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"strconv"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/configservice"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/sirupsen/logrus"

	check "github.com/adevinta/vulcan-check-sdk"
	"github.com/adevinta/vulcan-check-sdk/helpers"
	checkstate "github.com/adevinta/vulcan-check-sdk/state"
	report "github.com/adevinta/vulcan-report"
	"github.com/aws/aws-sdk-go/aws/arn"
)

var (
	checkName = "vulcan-aws-config-service"
	logger    = check.NewCheckLog(checkName)
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

func scanAccount(opt options, target, assetType string, logger *logrus.Entry, state checkstate.State) error {
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String("eu-west-1"),
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
	var ruleNames []string
	c := configservice.New(sess, &aws.Config{Credentials: creds})
	err = c.DescribeConfigRulesPages(&configservice.DescribeConfigRulesInput{}, func(o *configservice.DescribeConfigRulesOutput, b bool) bool {
		for _, rule := range o.ConfigRules {
			ruleNames = append(ruleNames, *rule.ConfigRuleName)
		}
		return false
	})
	if err != nil {
		return err
	}
	var alias *string
	for _, v := range ruleNames {
		o, err := c.DescribeConfigRules(&configservice.DescribeConfigRulesInput{ConfigRuleNames: aws.StringSlice([]string{v})})
		if err != nil {
			return err
		}
		rule := o.ConfigRules[0]
		in := &configservice.GetComplianceDetailsByConfigRuleInput{ConfigRuleName: aws.String(v), Limit: aws.Int64(100), ComplianceTypes: aws.StringSlice([]string{"NON_COMPLIANT"})}
		evaluationResults := []*configservice.EvaluationResult{}
		_ = c.GetComplianceDetailsByConfigRulePages(in, func(gacrcso *configservice.GetComplianceDetailsByConfigRuleOutput, b bool) bool {
			if gacrcso.NextToken == nil {
				evaluationResults = append(evaluationResults, gacrcso.EvaluationResults...)
				return false
			}
			evaluationResults = append(evaluationResults, gacrcso.EvaluationResults...)
			return true
		})

		description := ""
		recommendedActions := []string{}
		additionalResources := []string{}
		if rule.Description != nil {
			description = *rule.Description
		}
		var re = regexp.MustCompile(`(?m)Severity: (\d\.\d)`)

		match := re.FindAllStringSubmatch(*rule.Description, 1)
		var score float32 = 0.0
		if len(match) > 0 {
			s, _ := strconv.ParseFloat(match[0][1], 32)
			score = float32(s)
		}

		for _, evaluationResult := range evaluationResults {
			if alias == nil {
				res, err := accountAlias(creds)
				if err != nil {
					return err
				}
				alias = &res
			}
			row := map[string]string{"Account": *alias}
			header := []string{"Account"}
			occurrences := report.ResourcesGroup{
				Name: "Occurrences",
			}
			occurrences.Rows = append(occurrences.Rows, row)
			occurrences.Header = header

			summary := ""
			// Avoid nil pointer dereference when reading *rule.ConfigRuleName
			if rule.ConfigRuleName != nil {
				summary = "Config Rule " + *rule.ConfigRuleName
			}
			vuln := report.Vulnerability{
				Summary:                summary,
				Description:            description,
				Score:                  score,
				AffectedResource:       aws.StringValue(evaluationResult.EvaluationResultIdentifier.EvaluationResultQualifier.ResourceId),
				AffectedResourceString: aws.StringValue(evaluationResult.EvaluationResultIdentifier.EvaluationResultQualifier.ResourceId),
				Labels:                 []string{"issue", "aws", "config"},
				Resources:              []report.ResourcesGroup{occurrences},
			}
			vuln.Recommendations = append(vuln.Recommendations, recommendedActions...)
			vuln.References = append(vuln.References, additionalResources...)
			vuln.Fingerprint = helpers.ComputeFingerprint()

			state.AddVulnerabilities(vuln)
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
		logger.Errorf("cannot marshal request: %s", err.Error())
		return nil, err
	}
	req, err := http.NewRequest("GET", url, bytes.NewBuffer(jsonBody))
	if err != nil {
		logger.Errorf("cannot create request: %s", err.Error())
		return nil, err
	}
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

// accountAlias gets one of the current aliases of the account that the
// credentials passed belong to.
func accountAlias(creds *credentials.Credentials) (string, error) {
	svc := iam.New(session.New(&aws.Config{Credentials: creds}))
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
