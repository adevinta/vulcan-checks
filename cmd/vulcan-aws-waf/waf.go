/*
Copyright 2025 Adevinta
*/

package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/apigateway"
	"github.com/aws/aws-sdk-go-v2/service/apigatewayv2"
	"github.com/aws/aws-sdk-go-v2/service/cloudfront"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbv2types "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/wafv2"
	"github.com/sirupsen/logrus"
)

type ALBWAFStatus struct {
	Name        string
	Aliases     []string
	Region      string
	WAFEnabled  bool
	WAFRequired bool
}

type CloudFrontWAFStatus struct {
	DistributionID string
	Aliases        []string
	WAFEnabled     bool
	WAFRequired    bool
}

type APIGatewayWAFStatus struct {
	Name        string
	Type        string // REST or HTTP
	Aliases     []string
	WAFEnabled  bool
	WAFRequired bool
	Region      string
}

// route53Client represents a AWS Route 53 client.
type route53Client interface {
	ListHostedZones(ctx context.Context, params *route53.ListHostedZonesInput, optFns ...func(*route53.Options)) (*route53.ListHostedZonesOutput, error)
	ListResourceRecordSets(ctx context.Context, params *route53.ListResourceRecordSetsInput, optFns ...func(*route53.Options)) (*route53.ListResourceRecordSetsOutput, error)
}

// ec2Client represents a AWS EC2 client.
type ec2Client interface {
	DescribeRegions(ctx context.Context, params *ec2.DescribeRegionsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeRegionsOutput, error)
}

// cloudfrontClient represents a AWS CloudFront client.
type cloudfrontClient interface {
	ListDistributions(ctx context.Context, params *cloudfront.ListDistributionsInput, optFns ...func(*cloudfront.Options)) (*cloudfront.ListDistributionsOutput, error)
	ListTagsForResource(ctx context.Context, params *cloudfront.ListTagsForResourceInput, optFns ...func(*cloudfront.Options)) (*cloudfront.ListTagsForResourceOutput, error)
}

type Scanner struct {
	logger               *logrus.Entry
	wafRequiredTag       string
	target               string
	route53Client        route53Client
	ec2Client            ec2Client
	cloudfrontClient     cloudfrontClient
	elbv2ClientFactory   func(region string) *elasticloadbalancingv2.Client
	wafClientFactory     func(region string) *wafv2.Client
	restApiClientFactory func(region string) *apigateway.Client
	httpApiClientFactory func(region string) *apigatewayv2.Client
}

// NewScanner creates a new instance of the Scanner.
func NewScanner(ctx context.Context, logger *logrus.Entry, target string, wafRequiredTag string, cfg aws.Config) Scanner {
	return Scanner{
		logger:           logger,
		wafRequiredTag:   wafRequiredTag,
		target:           target,
		route53Client:    route53.NewFromConfig(cfg),
		ec2Client:        ec2.NewFromConfig(cfg),
		cloudfrontClient: cloudfront.NewFromConfig(cfg),
		elbv2ClientFactory: func(region string) *elasticloadbalancingv2.Client {
			cfg.Region = region
			return elasticloadbalancingv2.NewFromConfig(cfg)
		},
		wafClientFactory: func(region string) *wafv2.Client {
			cfg.Region = region
			return wafv2.NewFromConfig(cfg)
		},
		restApiClientFactory: func(region string) *apigateway.Client {
			cfg.Region = region
			return apigateway.NewFromConfig(cfg)
		},
		httpApiClientFactory: func(region string) *apigatewayv2.Client {
			cfg.Region = region
			return apigatewayv2.NewFromConfig(cfg)
		},
	}
}

func (s *Scanner) ScanALBs(ctx context.Context) ([]ALBWAFStatus, error) {
	var results []ALBWAFStatus

	regionOut, err := s.ec2Client.DescribeRegions(ctx, &ec2.DescribeRegionsInput{})
	if err != nil {
		return nil, err
	}

	for _, region := range regionOut.Regions {
		regionName := aws.ToString(region.RegionName)

		elbClient := s.elbv2ClientFactory(regionName)
		wafClient := s.wafClientFactory(regionName)

		lbs, err := elbClient.DescribeLoadBalancers(ctx, &elasticloadbalancingv2.DescribeLoadBalancersInput{})
		if err != nil {
			s.logger.Errorf("unable to describe load balancers in region %s: %v", regionName, err)
			continue
		}

		for _, lb := range lbs.LoadBalancers {
			if lb.Type != elbv2types.LoadBalancerTypeEnumApplication {
				continue
			}

			albName := aws.ToString(lb.LoadBalancerName)
			albArn := aws.ToString(lb.LoadBalancerArn)

			wafEnabled := false
			webAclOut, err := wafClient.GetWebACLForResource(ctx, &wafv2.GetWebACLForResourceInput{
				ResourceArn: aws.String(albArn),
			})
			if err == nil && webAclOut.WebACL != nil {
				wafEnabled = true
			}

			wafRequired := true
			tagRes, err := elbClient.DescribeTags(ctx, &elasticloadbalancingv2.DescribeTagsInput{
				ResourceArns: []string{albArn},
			})
			if err == nil {
				for _, tagDesc := range tagRes.TagDescriptions {
					for _, tag := range tagDesc.Tags {
						if aws.ToString(tag.Key) == s.wafRequiredTag && sanitizeTagValue(aws.ToString(tag.Value)) == "false" {
							wafRequired = false
						}
					}
				}
			}

			if !wafEnabled && !wafRequired {
				s.logger.Infof("ALB %s in region %s does not require WAF due to tag %s set to 'false'", albName, regionName, s.wafRequiredTag)
			}

			aliases, err := s.findRoute53Aliases(ctx, albName)
			if err != nil {
				s.logger.Warnf("unable to find Route 53 aliases for ALB %s in region %s: %v", albName, regionName, err)
			}

			results = append(results, ALBWAFStatus{
				Name:        albName,
				Region:      regionName,
				WAFEnabled:  wafEnabled,
				WAFRequired: wafRequired,
				Aliases:     deduplicateStrings(aliases),
			})
		}
	}

	return results, nil
}

func (s *Scanner) ScanCloudFrontDistributions(ctx context.Context) ([]CloudFrontWAFStatus, error) {
	var results []CloudFrontWAFStatus

	listOut, err := s.cloudfrontClient.ListDistributions(ctx, &cloudfront.ListDistributionsInput{})
	if err != nil {
		return nil, fmt.Errorf("unable to list CloudFront distributions: %w", err)
	}

	if listOut.DistributionList == nil || len(listOut.DistributionList.Items) == 0 {
		return results, nil
	}

	wafClient := s.wafClientFactory("us-east-1") // CloudFront WAF is always in us-east-1

	for _, dist := range listOut.DistributionList.Items {
		distID := aws.ToString(dist.Id)
		distARN := aws.ToString(dist.ARN)

		wafEnabled := false
		webAclOut, err := wafClient.GetWebACLForResource(ctx, &wafv2.GetWebACLForResourceInput{
			ResourceArn: aws.String(distARN),
		})
		if err == nil && webAclOut.WebACL != nil {
			wafEnabled = true
		}

		wafRequired := true
		tagOut, err := s.cloudfrontClient.ListTagsForResource(ctx, &cloudfront.ListTagsForResourceInput{
			Resource: aws.String(distARN),
		})
		if err == nil {
			for _, tag := range tagOut.Tags.Items {
				if aws.ToString(tag.Key) == s.wafRequiredTag && sanitizeTagValue(aws.ToString(tag.Value)) == "false" {
					wafRequired = false
				}
			}
		}

		if !wafEnabled && !wafRequired {
			s.logger.Infof("CloudFront distribution %s does not require WAF due to tag %s set to 'false'", distID, s.wafRequiredTag)
		}

		var aliases []string
		if dist.Aliases != nil {
			aliases = append(aliases, dist.Aliases.Items...)
		}

		results = append(results, CloudFrontWAFStatus{
			DistributionID: distID,
			Aliases:        deduplicateStrings(aliases),
			WAFEnabled:     wafEnabled,
			WAFRequired:    wafRequired,
		})
	}

	return results, nil
}

func (s *Scanner) ScanAPIGateways(ctx context.Context) ([]APIGatewayWAFStatus, error) {
	var results []APIGatewayWAFStatus

	regionOut, err := s.ec2Client.DescribeRegions(ctx, &ec2.DescribeRegionsInput{})
	if err != nil {
		return nil, err
	}

	for _, region := range regionOut.Regions {
		regionName := aws.ToString(region.RegionName)

		restClient := s.restApiClientFactory(regionName)
		httpClient := s.httpApiClientFactory(regionName)
		wafClient := s.wafClientFactory(regionName)

		// --- REST APIs (apigateway)
		restOut, err := restClient.GetRestApis(ctx, &apigateway.GetRestApisInput{})
		if err == nil {
			for _, api := range restOut.Items {
				apiID := aws.ToString(api.Id)
				apiArn := fmt.Sprintf("arn:aws:apigateway:%s::/restapis/%s/stages/*", regionName, apiID)

				wafEnabled := false
				wafOut, err := wafClient.GetWebACLForResource(ctx, &wafv2.GetWebACLForResourceInput{
					ResourceArn: aws.String(apiArn),
				})
				if err == nil && wafOut.WebACL != nil {
					wafEnabled = true
				}

				wafRequired := true
				tagsOut, err := restClient.GetTags(ctx, &apigateway.GetTagsInput{
					ResourceArn: aws.String(apiArn),
				})
				if err == nil {
					for k, v := range tagsOut.Tags {
						if k == s.wafRequiredTag && sanitizeTagValue(v) == "false" {
							wafRequired = false
						}
					}
				}

				results = append(results, APIGatewayWAFStatus{
					Name:        apiID,
					Type:        "REST",
					Region:      regionName,
					WAFEnabled:  wafEnabled,
					WAFRequired: wafRequired,
				})
			}
		}

		// --- HTTP APIs (apigatewayv2)
		httpOut, err := httpClient.GetApis(ctx, &apigatewayv2.GetApisInput{})
		if err == nil {
			for _, api := range httpOut.Items {
				apiID := aws.ToString(api.ApiId)
				apiArn := fmt.Sprintf("arn:aws:apigateway:%s::/apis/%s/stages/*", regionName, apiID)

				wafEnabled := false
				wafOut, err := wafClient.GetWebACLForResource(ctx, &wafv2.GetWebACLForResourceInput{
					ResourceArn: aws.String(apiArn),
				})
				if err == nil && wafOut.WebACL != nil {
					wafEnabled = true
				}

				wafRequired := true
				tagsOut, err := httpClient.GetTags(ctx, &apigatewayv2.GetTagsInput{
					ResourceArn: aws.String(apiArn),
				})
				if err == nil {
					for k, v := range tagsOut.Tags {
						if k == s.wafRequiredTag && sanitizeTagValue(v) == "false" {
							wafRequired = false
						}
					}
				}

				var domainNames []string
				domainsOut, err := httpClient.GetDomainNames(ctx, &apigatewayv2.GetDomainNamesInput{})
				if err == nil {
					for _, domain := range domainsOut.Items {
						for _, mapping := range domain.DomainNameConfigurations {
							if aws.ToString(mapping.ApiGatewayDomainName) != "" {
								domainNames = append(domainNames, aws.ToString(domain.DomainName))
							}
						}
					}
				}

				results = append(results, APIGatewayWAFStatus{
					Name:        apiID,
					Type:        "HTTP",
					Region:      regionName,
					WAFEnabled:  wafEnabled,
					WAFRequired: wafRequired,
					Aliases:     deduplicateStrings(domainNames),
				})
			}
		}
	}

	return results, nil
}

func sanitizeTagValue(value string) string {
	return strings.TrimSpace(strings.ToLower(value))
}

func deduplicateStrings(slice []string) []string {
	unique := make(map[string]struct{})
	for _, item := range slice {
		unique[item] = struct{}{}
	}

	result := make([]string, 0, len(unique))
	for item := range unique {
		result = append(result, item)
	}

	return result
}

func (s *Scanner) findRoute53Aliases(ctx context.Context, albName string) ([]string, error) {
	var aliases []string

	zonesOutput, err := s.route53Client.ListHostedZones(ctx, &route53.ListHostedZonesInput{})
	if err != nil {
		return aliases, err
	}

	for _, zone := range zonesOutput.HostedZones {
		recordsOutput, err := s.route53Client.ListResourceRecordSets(ctx, &route53.ListResourceRecordSetsInput{
			HostedZoneId: zone.Id,
		})
		if err != nil {
			continue
		}

		for _, record := range recordsOutput.ResourceRecordSets {
			if record.AliasTarget != nil && record.AliasTarget.DNSName != nil {
				if dns := *record.AliasTarget.DNSName; strings.Contains(dns, albName) {
					aliases = append(aliases, *record.Name)
				}
			}
		}
	}

	return aliases, nil
}
