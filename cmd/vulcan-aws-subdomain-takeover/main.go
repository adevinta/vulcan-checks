/*
Copyright 2025 Adevinta
*/

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"regexp"
	"slices"

	check "github.com/adevinta/vulcan-check-sdk"
	"github.com/adevinta/vulcan-check-sdk/helpers"
	"github.com/adevinta/vulcan-check-sdk/helpers/awshelpers"
	checkstate "github.com/adevinta/vulcan-check-sdk/state"
	report "github.com/adevinta/vulcan-report"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/route53/types"
	"github.com/sirupsen/logrus"
)

const checkName = "vulcan-aws-subdomain-takeover"

type options struct {
	Global bool `json:"global"`
}

func main() {
	run := func(ctx context.Context, target, assetType, optJSON string, state checkstate.State) error {
		opt := options{}
		if optJSON != "" {
			if err := json.Unmarshal([]byte(optJSON), &opt); err != nil {
				return err
			}
		}
		logger := check.NewCheckLogFromContext(ctx, checkName)
		if target == "" {
			return fmt.Errorf("check target missing")
		}
		scan, err := NewScanner(ctx, opt, logger, target)
		if err != nil {
			return fmt.Errorf("could not create scan: %w", err)
		}
		takeovers, err := scan.Run()
		if err != nil {
			return fmt.Errorf("scan: %w", err)
		}
		addVulnsToState(state, takeovers, target)
		return nil
	}
	c := check.NewCheckFromHandler(checkName, run)
	c.RunAndServe()
}

type awsConfigurator interface {
	getConfig(logger *logrus.Entry, target string) (aws.Config, error)
}
type Inventory interface {
	IsIPPublicInInventory(ip string) (bool, error)
}

// route53Client represents a AWS route 53 client.
type route53Client interface {
	ListHostedZones(context.Context, *route53.ListHostedZonesInput, ...func(*route53.Options)) (*route53.ListHostedZonesOutput, error)
	ListResourceRecordSets(ctx context.Context, params *route53.ListResourceRecordSetsInput, optFns ...func(*route53.Options)) (*route53.ListResourceRecordSetsOutput, error)
}

// ec2Client represents a AWS route EC2 client.
type ec2Client interface {
	DescribeRegions(ctx context.Context, params *ec2.DescribeRegionsInput, optFns ...func(*ec2.Options)) (*ec2.DescribeRegionsOutput, error)
	DescribeAddressesAttribute(context.Context, *ec2.DescribeAddressesAttributeInput, ...func(*ec2.Options)) (*ec2.DescribeAddressesAttributeOutput, error)
	DescribeNetworkInterfaces(ctx context.Context, params *ec2.DescribeNetworkInterfacesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error)
}

// ipRangesClient represents a IPRanges Client.
type ipRangesClient interface {
	GetPrefixes() (AWSPrefixes, error)
}

// Scanner represents a subdomain takeover scanner.
type Scanner struct {
	global         bool
	inventory      Inventory
	logger         *logrus.Entry
	target         string
	configurator   awsConfigurator
	route53Client  route53Client
	ec2Client      ec2Client
	ipRangesClient ipRangesClient
}

// aswConfig represents the AWS configuration.
type awsConfig struct{}

// NewScanner creates a new instance of the Scanner.
func NewScanner(ctx context.Context, opt options, logger *logrus.Entry, target string) (Scanner, error) {
	cfg, err := awsConfig{}.getConfig(ctx, logger, target)
	if err != nil {
		return Scanner{}, fmt.Errorf("get config: %w", err)
	}
	var inventory Inventory
	if opt.Global {
		inventory = NewCloudInventory(
			os.Getenv("CLOUD_INVENTORY_TOKEN"),
			os.Getenv("CLOUD_INVENTORY_ENDPOINT"),
		)
	}

	return Scanner{
		global:         opt.Global,
		inventory:      inventory,
		logger:         logger,
		target:         target,
		route53Client:  route53.NewFromConfig(cfg),
		ec2Client:      ec2.NewFromConfig(cfg),
		ipRangesClient: NewAWSIPRanges(),
	}, nil
}

// Run executes the scan.
func (s Scanner) Run() (map[string]string, error) {
	dnsRecords, err := s.getRoute53ARecords()
	if err != nil {
		return nil, fmt.Errorf("get DNS records: %w", err)
	}
	if len(dnsRecords) == 0 {
		return nil, nil
	}
	regions, err := s.getRegions()
	if err != nil {
		return nil, fmt.Errorf("get regions: %w", err)
	}
	elasticIPs, err := s.getIPs(regions)
	if err != nil {
		return nil, fmt.Errorf("get Elastic IPs: %w", err)
	}
	takeovers, err := s.calculateTakeovers(dnsRecords, elasticIPs)
	if err != nil {
		return nil, fmt.Errorf("calculate Takeovers: %w", err)
	}
	return takeovers, nil
}

// getConfig retrieves the AWS configuration to use with the AWS clients.
func (ac awsConfig) getConfig(ctx context.Context, logger *logrus.Entry, target string) (aws.Config, error) {
	if target == "" {
		return aws.Config{}, errors.New("target missing")
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
		return aws.Config{}, checkstate.ErrAssetUnreachable
	}
	return cfg, nil
}

// dnsRecord represents a subdomain.
type dnsRecord struct {
	name    string
	records []string
}

// getRoute53ARecords retrieves the DNS A records.
func (s Scanner) getRoute53ARecords() ([]dnsRecord, error) {
	var dnsRecords []dnsRecord

	hz, err := s.getRoute53HostedZones()
	if err != nil {
		return nil, fmt.Errorf("get hosted zones: %w", err)
	}

	for _, hostedZone := range hz {
		zr, err := s.getRoute53ZoneRecords(hostedZone.Id)
		if err != nil {
			return nil, fmt.Errorf("get zone records: %w", err)
		}
		for _, record := range zr {
			if record.Type == types.RRTypeA {
				if record.AliasTarget != nil {
					continue
				} else {
					var aRecords []string
					for _, rr := range record.ResourceRecords {
						aRecords = append(aRecords, *rr.Value)
					}
					r53Object := []dnsRecord{
						{
							name:    *record.Name,
							records: aRecords,
						},
					}
					dnsRecords = append(dnsRecords, r53Object...)
				}
			}
		}
	}
	return dnsRecords, nil
}

// getRoute53HostedZones retrieves all the hosted zones.
func (s Scanner) getRoute53HostedZones() ([]types.HostedZone, error) {
	paginator := route53.NewListHostedZonesPaginator(s.route53Client, nil)
	var hostedZones []types.HostedZone
	for paginator.HasMorePages() {
		resp, err := paginator.NextPage(context.Background())
		if err != nil {
			return nil, fmt.Errorf("list hosted zones: %w", err)
		}
		hostedZones = append(hostedZones, resp.HostedZones...)
	}
	return hostedZones, nil
}

// getRoute53ZoneRecords retrieves all the Zone Records for a ZoneId.
func (s Scanner) getRoute53ZoneRecords(zoneId *string) ([]types.ResourceRecordSet, error) {
	listParams := &route53.ListResourceRecordSetsInput{
		HostedZoneId: zoneId,
	}
	paginator := route53.NewListResourceRecordSetsPaginator(s.route53Client, listParams)
	var zoneRecords []types.ResourceRecordSet
	for paginator.HasMorePages() {
		resp, err := paginator.NextPage(context.Background())
		if err != nil {
			return nil, fmt.Errorf("list resource record sets: %w", err)
		}
		zoneRecords = append(zoneRecords, resp.ResourceRecordSets...)
	}
	return zoneRecords, nil
}

func (s Scanner) getRegions() ([]string, error) {
	var regions []string
	r, err := s.ec2Client.DescribeRegions(context.Background(), nil)
	if err != nil {
		return nil, fmt.Errorf("describe regions: %w", err)
	}
	for _, region := range r.Regions {
		regions = append(regions, *region.RegionName)
	}
	return regions, nil
}

// getIPs retrieve the public IPs.
func (s Scanner) getIPs(regions []string) ([]string, error) {
	var elasticIPs = make(map[string]interface{})
	for _, region := range regions {
		describeAddressesRegion := func(o *ec2.Options) {
			o.Region = region
		}
		// Get the public IPs from the addresses.
		paginatorAddresses := ec2.NewDescribeAddressesAttributePaginator(s.ec2Client, nil)
		for paginatorAddresses.HasMorePages() {
			resp, err := paginatorAddresses.NextPage(context.Background())
			if err != nil {
				return nil, fmt.Errorf("describe addresses: %w", err)
			}
			for _, address := range resp.Addresses {
				elasticIPs[*address.PublicIp] = nil
			}
		}

		// Get the public IPs from the Network Interfaces.
		paginatorNetworkInterfaces := ec2.NewDescribeNetworkInterfacesPaginator(s.ec2Client, nil)
		for paginatorNetworkInterfaces.HasMorePages() {
			resp, err := paginatorNetworkInterfaces.NextPage(context.Background(), describeAddressesRegion)
			if err != nil {
				return nil, fmt.Errorf("describe network interfaces: %w", err)
			}
			for _, networkInterface := range resp.NetworkInterfaces {
				if networkInterface.Association != nil {
					elasticIPs[*networkInterface.Association.PublicIp] = *networkInterface.Association.PublicIp
				}
			}
		}
	}

	return slices.Collect(maps.Keys(elasticIPs)), nil
}

// calculateTakeovers crosses the dnsRecords with the elasticIPs and determine which of the
// dnsRecords are dangling.
func (s Scanner) calculateTakeovers(dnsRecords []dnsRecord, elasticIPs []string) (map[string]string, error) {
	// find all DNS records that point to EC2 IP addresses.
	dnsEC2IPs := make(map[string][]string)
	aip, err := s.ipRangesClient.GetPrefixes()
	if err != nil {
		return nil, fmt.Errorf("get ip ranges: %w", err)
	}
	r := regexp.MustCompile("EC2")

	for _, dnsr := range dnsRecords {
		for _, record := range dnsr.records {
			awsMetadata, err := aip.GetPrefixByIP(record)
			if err != nil {
				if errors.Is(err, ErrPrefixNotFound) {
					continue
				}
				return nil, fmt.Errorf("getting AWS metadata for %s: %w", record, err)
			}
			if r.MatchString(awsMetadata.Service) {
				dnsEC2IPs[dnsr.name] = dnsr.records
			}
		}
	}

	takeovers := make(map[string]string)

	// check to see if any of the record sets we have, we don't own the elastic IPs.
	for name, dnsEC2IP := range dnsEC2IPs {
		for _, record := range dnsEC2IP {
			if !contains(elasticIPs, record) {
				if s.global {
					inInventory, err := s.inventory.IsIPPublicInInventory(record)
					if err != nil {
						return nil, fmt.Errorf("inventory: %w", err)
					}
					if !inInventory {
						takeovers[name] = record
					}
				} else {
					takeovers[name] = record
				}
			}
		}
	}
	return takeovers, nil
}

// contains detects if a string is in a string slice.
func contains(s []string, str string) bool {
	for _, v := range s {
		if v == str {
			return true
		}
	}
	return false
}

// addVulnsToState adds every takeover detected to the vulnerability report.
func addVulnsToState(state checkstate.State, takeovers map[string]string, target string) {
	if takeovers == nil {
		return
	}
	for dns, ip := range takeovers {
		state.AddVulnerabilities(
			report.Vulnerability{
				AffectedResource: dns,
				Labels:           []string{"issue", "subdomain-takeover"},
				Fingerprint:      helpers.ComputeFingerprint(target, dns, ip),
				Summary:          `AWS Route 53 record without Elastic IP (Subdomain Takeover)`,
				Score:            report.SeverityThresholdHigh,
				Description: "The Route 53 record is pointing to an Elastic IP that is not owned by the account. " +
					"This could lead to a subdomain takeover if the Elastic IP is released and taken by someone else.",
				References: []string{"https://www.owasp.org/index.php/Unvalidated_Redirects_and_Forwards_Cheat_Sheet"},
				Recommendations: []string{
					"Locate DNS records pointing to services or platforms that are no longer active or in use. \n" +
						"Delete any DNS entries (e.g., CNAME, A, or NS records) associated with these inactive services.",
					"If the subdomain is still needed, reclaim the service or resource the DNS is pointing to by " +
						"setting up the original service again with the same configuration.",
					"Audit all DNS records and ensure they are pointing to valid, active resources.\n" +
						"Check for any misconfigurations or unverified integrations with third-party services.",
					"Restrict the creation of DNS records to authorized personnel or implement strict DNS management " +
						"processes to reduce the chance of dangling records being created.",
					"Avoid wildcard DNS records (*.example.com) unless absolutely necessary, as they " +
						"can inadvertently expose unused subdomains to risk.",
				},
				Resources: []report.ResourcesGroup{
					{
						Name:   `Instances`,
						Header: []string{"Account", "Subdomain", "PublicIP"},
						Rows: []map[string]string{
							{
								"Account":   target,
								"Subdomain": dns,
								"PublicIP":  ip,
							},
						},
					},
				},
			},
		)
	}
}
