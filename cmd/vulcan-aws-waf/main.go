/*
Copyright 2025 Adevinta
*/

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	check "github.com/adevinta/vulcan-check-sdk"
	"github.com/adevinta/vulcan-check-sdk/helpers"
	"github.com/adevinta/vulcan-check-sdk/helpers/awshelpers"
	checkstate "github.com/adevinta/vulcan-check-sdk/state"
	report "github.com/adevinta/vulcan-report"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/sirupsen/logrus"
)

const (
	checkName = "vulcan-aws-waf"

	// WAFRequiredTag is the tag key used to lower the WAF requirement severity
	// if the tag is pressent and set to "false".
	// If the tag is not present, the check will assume that WAF is required.
	DefaultWAFRequiredTag = "WAFRequired"
)

type options struct {
	WAFRequiredTag string `json:"waf_required_tag"`
}

var (
	missingWAFIntegration = report.Vulnerability{
		CWEID:         693,
		Summary:       "AWS resource missing WAF integration",
		ImpactDetails: "An AWS resource without WAF integration enabled can lead to increased risk of web application attacks, such as SQL injection and cross-site scripting.",
		Score:         report.SeverityThresholdMedium,
		Recommendations: []string{
			"Enable WAF integration for your AWS resource to protect against common web application vulnerabilities.",
			fmt.Sprintf("In the case you think that WAF is not mandatory for this resource, consider adding the tag '%s' with value 'false' to the resource in order to lower the severity of this check.", DefaultWAFRequiredTag),
		},
		References: []string{
			"https://aws.amazon.com/blogs/aws/aws-web-application-firewall-waf-for-application-load-balancers/",
			"https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/distribution-web-awswaf.html",
		},
		Labels: []string{"compliance", "waf", "aws"},
		Resources: []report.ResourcesGroup{
			{
				Name: "AWS Resources WAF Status",
				Header: []string{
					"Resource",
					"Name",
					"Region",
					"Aliases",
					"WAF Enabled",
					"WAF Required",
				},
				Rows: []map[string]string{},
			},
		},
	}

	missingWAFIntegrationRiskAccepted = report.Vulnerability{
		CWEID:         693,
		Summary:       "AWS resource missing WAF integration (Risk Accepted)",
		ImpactDetails: "An AWS resource without WAF integration enabled can lead to increased risk of web application attacks, such as SQL injection and cross-site scripting.",
		Score:         report.SeverityThresholdLow,
		Recommendations: []string{
			"Enable WAF integration for your AWS resource to protect against common web application vulnerabilities.",
		},
		References: []string{
			"https://aws.amazon.com/blogs/aws/aws-web-application-firewall-waf-for-application-load-balancers/",
			"https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/distribution-web-awswaf.html",
		},
		Labels: []string{"compliance", "waf", "aws"},
		Resources: []report.ResourcesGroup{
			{
				Name: "AWS Resources WAF Status",
				Header: []string{
					"Resource",
					"Name",
					"Region",
					"Aliases",
					"WAF Enabled",
					"WAF Required",
				},
				Rows: []map[string]string{},
			},
		},
	}

	wafIntegrationEnabled = report.Vulnerability{
		Summary: "AWS resource with WAF integration enabled",
		Score:   report.SeverityThresholdNone,
		References: []string{
			"https://aws.amazon.com/blogs/aws/aws-web-application-firewall-waf-for-application-load-balancers/",
			"https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/distribution-web-awswaf.html",
		},
		Labels: []string{"informational", "waf", "aws"},
		Resources: []report.ResourcesGroup{
			{
				Name: "AWS Resources WAF Status",
				Header: []string{
					"Resource",
					"Name",
					"Region",
					"Aliases",
				},
				Rows: []map[string]string{},
			},
		},
	}
)

func main() {
	run := func(ctx context.Context, target, assetType, optJSON string, state checkstate.State) error {
		logger := check.NewCheckLogFromContext(ctx, checkName)

		var opt options
		if err := json.Unmarshal([]byte(optJSON), &opt); err != nil {
			return err
		}
		if opt.WAFRequiredTag == "" {
			opt.WAFRequiredTag = DefaultWAFRequiredTag
		}

		if target == "" {
			return fmt.Errorf("check target missing")
		}

		assumeRoleEndpoint := os.Getenv("VULCAN_ASSUME_ROLE_ENDPOINT")
		roleName := os.Getenv("ROLE_NAME")

		var cfg aws.Config
		var err error
		if assumeRoleEndpoint == "" {
			cfg, err = awshelpers.GetAwsConfig(ctx, target, roleName, 3600)
		} else {
			cfg, err = awshelpers.GetAwsConfigWithVulcanAssumeRole(ctx, assumeRoleEndpoint, target, roleName, 3600)
		}
		if err != nil {
			logger.Errorf("unable to get AWS config: %v", err)
			return checkstate.ErrAssetUnreachable
		}

		scanner := NewScanner(ctx, logger, target, opt.WAFRequiredTag, cfg)

		startTime := time.Now().UTC()
		albResults, err := scanner.ScanALBs(ctx)
		if err != nil {
			logger.Errorf("error scanning ALBs: %v", err)
			return err
		}
		logger.WithFields(logrus.Fields{
			"alb_count": len(albResults),
			"duration":  time.Since(startTime).Seconds(),
		}).Info("ALB scan completed")

		startTime = time.Now().UTC()
		cfResults, err := scanner.ScanCloudFrontDistributions(ctx)
		if err != nil {
			logger.Errorf("error scanning CloudFront distributions: %v", err)
			return err
		}
		logger.WithFields(logrus.Fields{
			"cf_count": len(cfResults),
			"duration": time.Since(startTime).Seconds(),
		}).Info("CloudFront scan completed")

		startTime = time.Now().UTC()
		apiGatewayResults, err := scanner.ScanAPIGateways(ctx)
		if err != nil {
			logger.Errorf("error scanning API Gateways: %v", err)
			return err
		}
		logger.WithFields(logrus.Fields{
			"api_gateway_count": len(apiGatewayResults),
			"duration":          time.Since(startTime).Seconds(),
		}).Info("API Gateway scan completed")

		// Prepare the report
		missingWAFIntegration.Resources[0].Rows = make([]map[string]string, 0)
		missingWAFIntegrationRiskAccepted.Resources[0].Rows = make([]map[string]string, 0)
		wafIntegrationEnabled.Resources[0].Rows = make([]map[string]string, 0)

		for _, alb := range albResults {
			var aliases string
			switch len(alb.Aliases) {
			case 0:
				aliases = ""
			case 1:
				aliases = alb.Aliases[0]
			default:
				logger.Infof("ALB %s has multiple aliases: %v", alb.Name, alb.Aliases)
				aliases = fmt.Sprintf("%s and %d more", alb.Aliases[0], len(alb.Aliases)-1)
			}
			row := map[string]string{
				"Resource":     "ALB",
				"Name":         alb.Name,
				"Region":       alb.Region,
				"Aliases":      aliases,
				"WAF Enabled":  fmt.Sprintf("%t", alb.WAFEnabled),
				"WAF Required": fmt.Sprintf("%t", alb.WAFRequired),
			}
			if !alb.WAFEnabled {
				if alb.WAFRequired {
					missingWAFIntegration.Resources[0].Rows = append(missingWAFIntegration.Resources[0].Rows, row)
				} else {
					missingWAFIntegrationRiskAccepted.Resources[0].Rows = append(missingWAFIntegrationRiskAccepted.Resources[0].Rows, row)
				}
			} else {
				wafIntegrationEnabled.Resources[0].Rows = append(wafIntegrationEnabled.Resources[0].Rows, row)
			}
		}

		for _, dist := range cfResults {
			var aliases string
			switch len(dist.Aliases) {
			case 0:
				aliases = ""
			case 1:
				aliases = dist.Aliases[0]
			default:
				logger.Infof("CloudFront distribution %s has multiple aliases: %v", dist.DistributionID, dist.Aliases)
				aliases = fmt.Sprintf("%s and %d more", dist.Aliases[0], len(dist.Aliases)-1)
			}
			row := map[string]string{
				"Resource":     "CloudFront",
				"Name":         dist.DistributionID,
				"Region":       "us-east-1", // CloudFront is always in us-east-1
				"Aliases":      aliases,
				"WAF Enabled":  fmt.Sprintf("%t", dist.WAFEnabled),
				"WAF Required": fmt.Sprintf("%t", dist.WAFRequired),
			}
			if !dist.WAFEnabled {
				if dist.WAFRequired {
					missingWAFIntegration.Resources[0].Rows = append(missingWAFIntegration.Resources[0].Rows, row)
				} else {
					missingWAFIntegrationRiskAccepted.Resources[0].Rows = append(missingWAFIntegrationRiskAccepted.Resources[0].Rows, row)
				}
			} else {
				wafIntegrationEnabled.Resources[0].Rows = append(wafIntegrationEnabled.Resources[0].Rows, row)
			}
		}

		for _, api := range apiGatewayResults {
			var aliases string
			switch len(api.Aliases) {
			case 0:
				aliases = ""
			case 1:
				aliases = api.Aliases[0]
			default:
				logger.Infof("API Gateway %s has multiple aliases: %v", api.Name, api.Aliases)
				aliases = fmt.Sprintf("%s and %d more", api.Aliases[0], len(api.Aliases)-1)
			}
			row := map[string]string{
				"Resource":     fmt.Sprintf("API Gateway (%s)", api.Type),
				"Name":         api.Name,
				"Region":       api.Region,
				"Aliases":      aliases,
				"WAF Enabled":  fmt.Sprintf("%t", api.WAFEnabled),
				"WAF Required": fmt.Sprintf("%t", api.WAFRequired),
			}
			if !api.WAFEnabled {
				if api.WAFRequired {
					missingWAFIntegration.Resources[0].Rows = append(missingWAFIntegration.Resources[0].Rows, row)
				} else {
					missingWAFIntegrationRiskAccepted.Resources[0].Rows = append(missingWAFIntegrationRiskAccepted.Resources[0].Rows, row)
				}
			} else {
				wafIntegrationEnabled.Resources[0].Rows = append(wafIntegrationEnabled.Resources[0].Rows, row)
			}
		}

		if len(missingWAFIntegration.Resources[0].Rows) > 0 {
			// Sort the resource names for consistent fingerprinting
			sortedResourceNames := make([]string, 0, len(missingWAFIntegration.Resources[0].Rows))
			for _, row := range missingWAFIntegration.Resources[0].Rows {
				sortedResourceNames = append(sortedResourceNames, row["Name"])
			}
			sort.Strings(sortedResourceNames)
			missingWAFIntegration.Fingerprint = helpers.ComputeFingerprint(sortedResourceNames)

			// If the WAFRequiredTag is set to something other than the default, update the recommendations
			if opt.WAFRequiredTag != DefaultWAFRequiredTag {
				for i, recommendation := range missingWAFIntegration.Recommendations {
					r := strings.ReplaceAll(recommendation, DefaultWAFRequiredTag, opt.WAFRequiredTag)
					missingWAFIntegration.Recommendations[i] = r
				}
			}
			// Add the vulnerability to the state
			state.AddVulnerabilities(missingWAFIntegration)
		}
		if len(missingWAFIntegrationRiskAccepted.Resources[0].Rows) > 0 {
			// Sort the resource names for consistent fingerprinting
			sortedResourceNames := make([]string, 0, len(missingWAFIntegrationRiskAccepted.Resources[0].Rows))
			for _, row := range missingWAFIntegrationRiskAccepted.Resources[0].Rows {
				sortedResourceNames = append(sortedResourceNames, row["Name"])
			}
			sort.Strings(sortedResourceNames)
			missingWAFIntegrationRiskAccepted.Fingerprint = helpers.ComputeFingerprint(sortedResourceNames)
			// If the WAFRequiredTag is set to something other than the default, update the recommendations
			state.AddVulnerabilities(missingWAFIntegrationRiskAccepted)
		}
		if len(wafIntegrationEnabled.Resources[0].Rows) > 0 {
			// Sort the resource names for consistent fingerprinting
			sortedResourceNames := make([]string, 0, len(wafIntegrationEnabled.Resources[0].Rows))
			for _, row := range wafIntegrationEnabled.Resources[0].Rows {
				sortedResourceNames = append(sortedResourceNames, row["Name"])
			}
			sort.Strings(sortedResourceNames)
			wafIntegrationEnabled.Fingerprint = helpers.ComputeFingerprint(sortedResourceNames)
			// If the WAFRequiredTag is set to something other than the default, update the recommendations
			state.AddVulnerabilities(wafIntegrationEnabled)
		}

		return nil
	}

	c := check.NewCheckFromHandler(checkName, run)
	c.RunAndServe()
}
