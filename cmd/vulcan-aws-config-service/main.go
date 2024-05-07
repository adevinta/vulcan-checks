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
	RefreshTimeout int      `json:"refresh_timeout"`
	Regions        []string `json:"regions"`
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
		if len(opt.Regions) == 0 {
			opt.Regions = []string{"eu-west-1"}
		}
		return scanAccount(target, assetType, logger, state, opt.Regions)
	}
	c := check.NewCheckFromHandler(checkName, run)
	c.RunAndServe()

}

func scanAccount(target, assetType string, logger *logrus.Entry, state checkstate.State, regions []string) error {
	var err error = nil
	for _, region := range regions {
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
		var cfg aws.Config
		if os.Getenv("AWS_PROFILE") != "" {
			defaultCfg, err := config.LoadDefaultConfig(context.Background(),
				config.WithRegion(region),
			)
			if err != nil {
				return fmt.Errorf("unable to create AWS config: %w", err)
			}
			cfg = defaultCfg
		} else {
			creds, err := getCredentials(assumeRoleEndpoint, parsedARN.AccountID, role, logger)
			if err != nil {
				return err
			}
			credsProvider := credentials.NewStaticCredentialsProvider(creds.AccessKeyID, creds.SecretAccessKey, creds.SessionToken)
			stsCfg, err := config.LoadDefaultConfig(context.Background(),
				config.WithRegion(region),
				config.WithCredentialsProvider(credsProvider),
			)
			if err != nil {
				return fmt.Errorf("unable to create AWS config: %w", err)
			}
			cfg = stsCfg
		}

		configserviceClient := configservice.NewFromConfig(cfg)
		ec2Client := ec2.NewFromConfig(cfg)
		paginator := configservice.NewDescribeConfigRulesPaginator(configserviceClient, &configservice.DescribeConfigRulesInput{})
		pageNum := 0
		ruleNames := []string{}
		for paginator.HasMorePages() {
			output, err := paginator.NextPage(context.Background())
			if err != nil {
				return err
			}
			for _, rule := range output.ConfigRules {
				ruleNames = append(ruleNames, *rule.ConfigRuleName)
			}
			pageNum++
		}
		if err != nil {
			return fmt.Errorf("error getting config rules: %v", err)
		}
		var alias *string
		for _, v := range ruleNames {
			o, err := configserviceClient.DescribeConfigRules(context.Background(), &configservice.DescribeConfigRulesInput{ConfigRuleNames: []string{v}})
			if err != nil {
				return fmt.Errorf("error describing config rules: %v", err)
			}
			rule := o.ConfigRules[0]
			evaluationResults := []types.EvaluationResult{}
			p := configservice.NewGetComplianceDetailsByConfigRulePaginator(configserviceClient, &configservice.GetComplianceDetailsByConfigRuleInput{ConfigRuleName: aws.String(v), Limit: 100, ComplianceTypes: []types.ComplianceType{types.ComplianceTypeNonCompliant}})
			pageNum := 0
			for p.HasMorePages() {
				output, err := p.NextPage(context.Background())
				if err != nil {
					return err
				}
				evaluationResults = append(evaluationResults, output.EvaluationResults...)
				pageNum++
			}

			description := ""
			recommendedActions := []string{}
			additionalResources := []string{"https://docs.aws.amazon.com/config/latest/developerguide/WhatIsConfig.html"}
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
				FinalScore := score
				details := "Region: " + region + "\n\n"
				if alias == nil {
					res, err := accountAlias(cfg)
					if err != nil {
						return fmt.Errorf("error getting account alias: %v", err)
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

				r, err := configserviceClient.GetResourceConfigHistory(context.Background(), &configservice.GetResourceConfigHistoryInput{
					Limit:        1,
					ResourceId:   evaluationResult.EvaluationResultIdentifier.EvaluationResultQualifier.ResourceId,
					ResourceType: types.ResourceType(*evaluationResult.EvaluationResultIdentifier.EvaluationResultQualifier.ResourceType),
				})
				if err != nil {
					logger.Printf("error getting config rule state: %v", err)
				} else {
					if evaluationResult.Annotation != nil {
						if !(*rule.Source.SourceIdentifier == "VPC_SG_OPEN_ONLY_TO_AUTHORIZED_PORTS" || *rule.Source.SourceIdentifier == "RESTRICTED_INCOMING_TRAFFIC") {
							details = details + *evaluationResult.Annotation
						}
					}
					if *evaluationResult.EvaluationResultIdentifier.EvaluationResultQualifier.ResourceType == "AWS::EC2::SecurityGroup" {
						if r.ConfigurationItems[0].Relationships != nil {
							if !isUsed(r.ConfigurationItems[0].Relationships) {
								FinalScore = 0.0
								details = details + "\n\nUnused Security group"
							}
							if rule.Source.Owner == types.OwnerAws && (*rule.Source.SourceIdentifier == "VPC_SG_OPEN_ONLY_TO_AUTHORIZED_PORTS" || *rule.Source.SourceIdentifier == "RESTRICTED_INCOMING_TRAFFIC") && !isPublic(r.ConfigurationItems[0].Relationships, *ec2Client) {
								FinalScore = 0.0
								details = details + "\nPrivate Network"
							}
						}
						if r.ConfigurationItems[0].Configuration != nil {
							c := &SGConfiguration{}
							err := json.Unmarshal([]byte(*r.ConfigurationItems[0].Configuration), &c)
							if err != nil {
								logger.Printf("error getting config rule state: %v", err)
							}
							details = details + fmt.Sprintf("\n\nSecurity Group Name: %s", c.GroupName)
							details = details + fmt.Sprintf("\nSecurity Group Description: %s", c.Description)
							details = details + "\nSecurity Group Rules:"

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
										}
									}
								}
							}
						}
					}
				}

				vuln := report.Vulnerability{
					Summary:                summary,
					Description:            description,
					Score:                  FinalScore,
					AffectedResource:       *evaluationResult.EvaluationResultIdentifier.EvaluationResultQualifier.ResourceId,
					AffectedResourceString: *evaluationResult.EvaluationResultIdentifier.EvaluationResultQualifier.ResourceId,
					Labels:                 []string{"issue", "aws", "config"},
					Resources:              []report.ResourcesGroup{occurrences},
					Details:                details,
				}
				vuln.Recommendations = append(vuln.Recommendations, recommendedActions...)
				vuln.References = append(vuln.References, additionalResources...)
				vuln.Fingerprint = helpers.ComputeFingerprint()

				state.AddVulnerabilities(vuln)
			}

		}
	}
	return err
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

// AssumeRoleResponse represent a response from vulcan-assume-role
type AssumeRoleResponse struct {
	AccessKey       string `json:"access_key"`
	SecretAccessKey string `json:"secret_access_key"`
	SessionToken    string `json:"session_token"`
}

func getCredentials(url string, accountID, role string, logger *logrus.Entry) (*aws.Credentials, error) {
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
