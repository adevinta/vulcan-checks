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
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/configservice"
	"github.com/aws/aws-sdk-go-v2/service/configservice/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/sirupsen/logrus"

	check "github.com/adevinta/vulcan-check-sdk"
	"github.com/adevinta/vulcan-check-sdk/helpers"
	checkstate "github.com/adevinta/vulcan-check-sdk/state"
	report "github.com/adevinta/vulcan-report"
)

var (
	checkName = "vulcan-aws-config-service"
	logger    = check.NewCheckLog(checkName)
)

type options struct {
	Regions []string `json:"regions"`
}

type SGConfiguration struct {
	Description   string `json:"description"`
	GroupName     string `json:"groupName"`
	IPPermissions []struct {
		FromPort         int           `json:"fromPort"`
		IPProtocol       string        `json:"ipProtocol"`
		Ipv6Ranges       []interface{} `json:"ipv6Ranges"`
		PrefixListIds    []interface{} `json:"prefixListIds"`
		ToPort           int           `json:"toPort"`
		UserIDGroupPairs []interface{} `json:"userIdGroupPairs"`
		Ipv4Ranges       []struct {
			CidrIP string `json:"cidrIp"`
		} `json:"ipv4Ranges"`
		IPRanges []string `json:"ipRanges"`
	} `json:"ipPermissions"`
}

// AssumeRoleResponse represent a response from vulcan-assume-role
type AssumeRoleResponse struct {
	AccessKey       string `json:"access_key"`
	SecretAccessKey string `json:"secret_access_key"`
	SessionToken    string `json:"session_token"`
}

type Rule struct {
	Summary                string
	Description            string
	Severity               float32
	Remediation            string
	AffectedResourceString string
	Details                string
	Resources              []report.ResourcesGroup
}

func getAllRegions() ([]string, error) {
	ec2Client := ec2.NewFromConfig(aws.Config{
		Region: "eu-west-1",
	})
	r, err := ec2Client.DescribeRegions(context.Background(), &ec2.DescribeRegionsInput{})
	if err != nil {
		return nil, err
	}
	var regions []string
	for _, r := range r.Regions {
		regions = append(regions, *r.RegionName)
	}
	return regions, nil
}

func getAssumeRoleCredentials(url string, accountID, role string, logger *logrus.Entry) (*aws.Credentials, error) {
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
	creds := aws.Credentials{
		AccessKeyID:     assumeRoleResponse.AccessKey,
		SecretAccessKey: assumeRoleResponse.SecretAccessKey,
		SessionToken:    assumeRoleResponse.SessionToken,
	}
	return &creds, nil
}

func scanAccount(target, assetType string, logger *logrus.Entry, state checkstate.State, regions []string) error {
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
	if len(regions) == 0 {
		regions, err = getAllRegions()
		if err != nil {
			return fmt.Errorf("error getting regions: %v", err)
		}
	}
	offendingRules := make(map[string][]Rule)
	for _, region := range regions {
		cfg, err := getConfig(region, assumeRoleEndpoint, parsedARN.AccountID, role)
		if err != nil {
			return fmt.Errorf("error getting aws client config for region %s: %v", region, err)
		}

		configserviceClient := configservice.NewFromConfig(cfg)

		ruleNames, err := getRuleNames(configserviceClient)
		if err != nil {
			return fmt.Errorf("error describing config rules for region %s: %v", region, err)
		}

		regionOffendingRules, err := getOffendingRules(cfg, configserviceClient, ruleNames, region)
		if err != nil {
			return fmt.Errorf("error getting rules for region %s: %v", region, err)
		}
		for rule := range regionOffendingRules {
			offendingRules[rule] = append(offendingRules[rule], regionOffendingRules[rule]...)
		}
	}
	reportResults(offendingRules, target, state)
	return err
}

func reportResults(offendingRules map[string][]Rule, target string, state checkstate.State) {
	for _, rules := range offendingRules {
		var affectedResources []report.ResourcesGroup
		for _, hit := range rules {
			affectedResources = append(affectedResources, hit.Resources...)
		}
		vuln := report.Vulnerability{
			Summary:                rules[0].Description,
			Description:            rules[0].Description,
			Score:                  rules[0].Severity,
			AffectedResource:       target,
			AffectedResourceString: target,
			Labels:                 []string{"compliance", "aws", "config"},
			Resources:              affectedResources,
			Details:                rules[0].Description,
		}
		vuln.Recommendations = append(vuln.Recommendations, rules[0].Remediation)
		vuln.References = append(vuln.References, "https://docs.aws.amazon.com/config/latest/developerguide/WhatIsConfig.html")
		vuln.Fingerprint = helpers.ComputeFingerprint()
		state.AddVulnerabilities(vuln)
	}
}

func getOffendingRules(cfg aws.Config, configserviceClient *configservice.Client, ruleNames []string, region string) (map[string][]Rule, error) {
	var alias *string
	ec2Client := ec2.NewFromConfig(cfg)
	rules := make(map[string][]Rule)
	for _, ruleName := range ruleNames {
		o, err := configserviceClient.DescribeConfigRules(context.Background(), &configservice.DescribeConfigRulesInput{ConfigRuleNames: []string{ruleName}})
		if err != nil {
			return rules, fmt.Errorf("error describing config rules: %v", err)
		}
		rule := o.ConfigRules[0]
		evaluationResults := []types.EvaluationResult{}
		p := configservice.NewGetComplianceDetailsByConfigRulePaginator(configserviceClient, &configservice.GetComplianceDetailsByConfigRuleInput{ConfigRuleName: aws.String(ruleName), Limit: 100, ComplianceTypes: []types.ComplianceType{types.ComplianceTypeNonCompliant}})
		pageNum := 0
		for p.HasMorePages() {
			output, err := p.NextPage(context.Background())
			if err != nil {
				return rules, err
			}
			evaluationResults = append(evaluationResults, output.EvaluationResults...)
			pageNum++
		}

		description := ""
		recommendedActions := []string{}

		if rule.Description != nil {
			description = *rule.Description
		}
		var re = regexp.MustCompile(`(?m)Severity: (\d\.\d)`)
		match := re.FindAllStringSubmatch(description, 1)
		var score float32 = 0.0
		if len(match) > 0 {
			s, _ := strconv.ParseFloat(match[0][1], 32)
			score = float32(s)
		}

		re = regexp.MustCompile(`(?m)Remediation: (.*)`)
		match = re.FindAllStringSubmatch(description, 1)
		if len(match) > 0 {
			recommendedActions = append(recommendedActions, match[0][1])
		}

		for _, evaluationResult := range evaluationResults {
			var resources []report.ResourcesGroup
			details := "Region: " + region + "\n\n"
			if alias == nil {
				res, err := accountAlias(cfg)
				if err != nil {
					return rules, fmt.Errorf("error getting account alias: %v", err)
				}
				alias = &res
			}

			summary := ""
			// Avoid nil pointer dereference when reading *rule.ConfigRuleName
			if rule.ConfigRuleName != nil {
				summary = "Config Rule " + *rule.ConfigRuleName
			}

			r, err := configserviceClient.GetResourceConfigHistory(context.Background(), &configservice.GetResourceConfigHistoryInput{
				Limit:        1,
				ResourceId:   evaluationResult.EvaluationResultIdentifier.EvaluationResultQualifier.ResourceId,
				ResourceType: types.ResourceType(*evaluationResult.EvaluationResultIdentifier.EvaluationResultQualifier.ResourceType),
			})
			if err != nil {
				logger.Printf("error getting config rule state: %v", err)
				continue
			} else {
				var rs []report.ResourcesGroup
				var d string
				rs, d = getOffendingResources(evaluationResult, r, rule, *ec2Client)
				resources = append(resources, rs...)
				fmt.Printf("additional details: %s\n", d)
				fmt.Printf("resources: %v\n", resources)
				details = details + d
			}
			rules[*rule.ConfigRuleName] = append(rules[*rule.ConfigRuleName], Rule{
				Summary:                summary,
				Description:            description,
				Severity:               score,
				Remediation:            recommendedActions[0],
				AffectedResourceString: *evaluationResult.EvaluationResultIdentifier.EvaluationResultQualifier.ResourceId,
				Resources:              resources,
				Details:                details,
			})
		}
	}
	return rules, nil
}

func getOffendingResources(evaluationResult types.EvaluationResult, r *configservice.GetResourceConfigHistoryOutput, rule types.ConfigRule, ec2Client ec2.Client) ([]report.ResourcesGroup, string) {
	var affectedResources []report.ResourcesGroup
	var details string
	if evaluationResult.Annotation != nil {
		if !(*rule.Source.SourceIdentifier == "VPC_SG_OPEN_ONLY_TO_AUTHORIZED_PORTS" || *rule.Source.SourceIdentifier == "RESTRICTED_INCOMING_TRAFFIC") {
			details = details + *evaluationResult.Annotation
			affectedResources = append(affectedResources, report.ResourcesGroup{
				Name:   "Affected Resource",
				Header: []string{"Security Group"},
				Rows: []map[string]string{
					{"Security Group": *evaluationResult.EvaluationResultIdentifier.EvaluationResultQualifier.ResourceId},
				},
			})
		}
	}
	if *evaluationResult.EvaluationResultIdentifier.EvaluationResultQualifier.ResourceType == "AWS::EC2::SecurityGroup" {
		if r.ConfigurationItems[0].Relationships != nil {
			if !isUsed(r.ConfigurationItems[0].Relationships) {
				return nil, details
			}
			if rule.Source.Owner == types.OwnerAws && (*rule.Source.SourceIdentifier == "VPC_SG_OPEN_ONLY_TO_AUTHORIZED_PORTS" || *rule.Source.SourceIdentifier == "RESTRICTED_INCOMING_TRAFFIC") && !isPublic(r.ConfigurationItems[0].Relationships, ec2Client) {
				return nil, details
			}
			if r.ConfigurationItems[0].Configuration != nil {
				c := &SGConfiguration{}
				err := json.Unmarshal([]byte(*r.ConfigurationItems[0].Configuration), &c)
				if err != nil {
					logger.Printf("error getting config rule state: %v", err)
					return nil, details
				}
				details = details + fmt.Sprintf("\n\nSecurity Group Name: %s", c.GroupName)
				details = details + fmt.Sprintf("\nSecurity Group Description: %s", c.Description)
				details = details + "\nSecurity Group Rules:"
				affectedResources = append(affectedResources, report.ResourcesGroup{
					Name:   "Security Group Rules",
					Header: []string{"RuleID", "Protocol", "FromPort", "ToPort", "IPRange"},
					Rows:   []map[string]string{},
				})

				r, err := ec2Client.DescribeSecurityGroupRules(context.Background(), &ec2.DescribeSecurityGroupRulesInput{
					Filters: []ec2types.Filter{
						{
							Name:   aws.String("group-id"),
							Values: []string{*r.ConfigurationItems[0].ResourceId},
						}}})
				if err != nil {
					logger.Printf("error getting config rules: %v", err)
				} else {
					if len(r.SecurityGroupRules) > 0 {
						for _, rule := range r.SecurityGroupRules {
							if !*rule.IsEgress {
								IpRange := ""
								if rule.CidrIpv4 != nil {
									IpRange = *rule.CidrIpv4
								}
								if rule.CidrIpv6 != nil {
									IpRange = *rule.CidrIpv6
								}
								details = details + fmt.Sprintf("\n    - RuleID: %s, Protocol: %s, FromPort: %d, ToPort: %d, IPRange: %v", *rule.SecurityGroupRuleId, *rule.IpProtocol, *rule.FromPort, *rule.ToPort, IpRange)
								affectedResources[1].Rows = append(affectedResources[1].Rows, map[string]string{
									"RuleID":   *rule.SecurityGroupRuleId,
									"Protocol": *rule.IpProtocol,
									"FromPort": strconv.Itoa(int(*rule.FromPort)),
									"ToPort":   strconv.Itoa(int(*rule.ToPort)),
									"IPRange":  IpRange,
								})
							}
						}
					}
				}
			}
		}
	}
	return affectedResources, details
}

func getRuleNames(configserviceClient *configservice.Client) ([]string, error) {
	paginator := configservice.NewDescribeConfigRulesPaginator(configserviceClient, &configservice.DescribeConfigRulesInput{})
	ruleNames := []string{}
	pageNum := 0
	for paginator.HasMorePages() {
		output, err := paginator.NextPage(context.Background())
		if err != nil {
			return ruleNames, err
		}
		for _, rule := range output.ConfigRules {
			if strings.HasPrefix(*rule.ConfigRuleName, "guard-rails-") {
				ruleNames = append(ruleNames, *rule.ConfigRuleName)
			}
		}
		pageNum++
	}
	return ruleNames, nil
}

func getConfig(region string, assumeRoleEndpoint string, accountID string, role string) (aws.Config, error) {
	var cfg aws.Config
	if os.Getenv("AWS_PROFILE") != "" {
		defaultCfg, err := config.LoadDefaultConfig(context.Background(),
			config.WithRegion(region),
		)
		if err != nil {
			return cfg, fmt.Errorf("unable to create AWS config: %w", err)
		}
		cfg = defaultCfg
	} else {
		creds, err := getAssumeRoleCredentials(assumeRoleEndpoint, accountID, role, logger)
		if err != nil {
			return cfg, err
		}
		credsProvider := credentials.NewStaticCredentialsProvider(creds.AccessKeyID, creds.SecretAccessKey, creds.SessionToken)
		stsCfg, err := config.LoadDefaultConfig(context.Background(),
			config.WithRegion(region),
			config.WithCredentialsProvider(credsProvider),
		)
		if err != nil {
			return cfg, fmt.Errorf("unable to create AWS config: %w", err)
		}
		cfg = stsCfg
	}
	return cfg, nil
}

func isUsed(relationships []types.Relationship) bool {
	isUsed := false
	for _, r := range relationships {
		if string(r.ResourceType) != "AWS::EC2::VPC" {
			isUsed = true
		}
	}
	return isUsed
}

func isPublic(relationships []types.Relationship, ec2Client ec2.Client) bool {
	isPublic := false
	for _, r := range relationships {
		if r.ResourceType == types.ResourceTypeNetworkInterface {
			i, _ := ec2Client.DescribeNetworkInterfaces(context.Background(), &ec2.DescribeNetworkInterfacesInput{
				NetworkInterfaceIds: []string{*r.ResourceId},
			})
			if i.NetworkInterfaces[0].Status == "in-use" && i.NetworkInterfaces[0].Association != nil && i.NetworkInterfaces[0].Association.PublicIp != nil {
				isPublic = true
			}
		}
	}
	return isPublic
}

// accountAlias gets one of the current aliases of the account that the
// credentials passed belong to.
func accountAlias(cfg aws.Config) (string, error) {
	svc := iam.NewFromConfig(cfg)
	resp, err := svc.ListAccountAliases(context.Background(), &iam.ListAccountAliasesInput{})
	if err != nil {
		return "", err
	}
	if len(resp.AccountAliases) == 0 {
		// No aliases found for the aws account.
		return "", nil
	}
	if len(resp.AccountAliases) < 1 {
		return "", errors.New("no result getting aliases for aws account")
	}
	a := resp.AccountAliases[0]
	return a, nil
}

func main() {
	run := func(ctx context.Context, target, assetType, optJSON string, state checkstate.State) error {
		if target == "" {
			return fmt.Errorf("check target missing")
		}
		opt := options{}
		err := json.Unmarshal([]byte(optJSON), &opt)
		if err != nil {
			return fmt.Errorf("error unmarshalling options: %v", err)
		}
		return scanAccount(target, assetType, logger, state, opt.Regions)
	}
	c := check.NewCheckFromHandler(checkName, run)
	c.RunAndServe()
}
