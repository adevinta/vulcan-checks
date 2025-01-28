/*
Copyright 2025 Adevinta
*/

package main

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"slices"
	"strings"

	check "github.com/adevinta/vulcan-check-sdk"
	"github.com/adevinta/vulcan-check-sdk/helpers"
	checkstate "github.com/adevinta/vulcan-check-sdk/state"
	report "github.com/adevinta/vulcan-report"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/route53/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/sirupsen/logrus"
)

const checkName = "vulcan-subdomain-takeover"

// ErrTargetUnreachable means that it couldn't possible to reach the AWS target account.
var ErrTargetUnreachable = errors.New("target is Unreachable")

func main() {
	run := func(ctx context.Context, target, assetType, optJSON string, state checkstate.State) error {
		logger := check.NewCheckLogFromContext(ctx, checkName)

		if target == "" {
			return fmt.Errorf("check target missing")
		}
		scan, err := NewScan(logger, target)
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

type route53Client interface {
	ListHostedZones(context.Context, *route53.ListHostedZonesInput, ...func(*route53.Options)) (*route53.ListHostedZonesOutput, error)
	ListResourceRecordSets(ctx context.Context, params *route53.ListResourceRecordSetsInput, optFns ...func(*route53.Options)) (*route53.ListResourceRecordSetsOutput, error)
}

type ec2Client interface {
	DescribeAddressesAttribute(context.Context, *ec2.DescribeAddressesAttributeInput, ...func(*ec2.Options)) (*ec2.DescribeAddressesAttributeOutput, error)
	DescribeNetworkInterfaces(ctx context.Context, params *ec2.DescribeNetworkInterfacesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error)
}

type ipRangesClient interface {
	GetPrefixes() (AWSPrefixes, error)
}

type Scanner struct {
	logger         *logrus.Entry
	target         string
	configurator   awsConfigurator
	route53Client  route53Client
	ec2Client      ec2Client
	ipRangesClient ipRangesClient
}

type awsConfig struct{}

func NewScan(logger *logrus.Entry, target string) (Scanner, error) {
	cfg, err := awsConfig{}.getConfig(logger, target)
	if err != nil {
		return Scanner{}, fmt.Errorf("get config: %w", err)
	}
	return Scanner{
		logger:         logger,
		target:         target,
		route53Client:  route53.NewFromConfig(cfg),
		ec2Client:      ec2.NewFromConfig(cfg),
		ipRangesClient: NewAWSIPRanges(),
	}, nil
}

func (s Scanner) Run() ([]string, error) {
	dnsRecords, err := s.getRoute53ARecords()
	if err != nil {
		return nil, fmt.Errorf("get DNS records: %w", err)
	}
	elasticIPs, err := s.getIPs()
	if err != nil {
		return nil, fmt.Errorf("get Elastic IPs: %w", err)
	}
	takeovers, err := s.calculateTakeovers(dnsRecords, elasticIPs)
	if err != nil {
		return nil, fmt.Errorf("calculate Takeovers: %w", err)
	}
	return takeovers, nil
}

func (ac awsConfig) getConfig(logger *logrus.Entry, target string) (aws.Config, error) {
	if target == "" {
		return aws.Config{}, errors.New("target missing")
	}
	assumeRoleEndpoint := os.Getenv("VULCAN_ASSUME_ROLE_ENDPOINT")
	role := os.Getenv("ROLE_NAME")

	parsedARN, err := arn.Parse(target)
	if err != nil {
		return aws.Config{}, fmt.Errorf("parse ARN: %w", err)
	}
	var cfg aws.Config
	var creds aws.Credentials
	if assumeRoleEndpoint != "" {
		cs := NewCredentialsService(logger)
		c, err := cs.GetCredentials(assumeRoleEndpoint, parsedARN.AccountID, role)
		if err != nil {
			if errors.Is(err, ErrNoCredentials) {
				return aws.Config{}, ErrTargetUnreachable
			}
			return aws.Config{}, fmt.Errorf("get AWS credentials: %w", err)
		}
		creds = *c
	} else {
		// try to access with the default credentials.
		// TODO: Review when the error should be an checkstate.ErrAssetUnreachable (INCONCLUSIVE)
		cfg, err = config.LoadDefaultConfig(context.Background(), config.WithRegion("eu-west-1"))
		if err != nil {
			return aws.Config{}, fmt.Errorf("unable to create AWS config: %w", err)
		}
		stsSvc := sts.NewFromConfig(cfg)
		roleArn := fmt.Sprintf("arn:aws:iam::%s:role/%s", parsedARN.AccountID, role)
		prov := stscreds.NewAssumeRoleProvider(stsSvc, roleArn)
		creds, err = prov.Retrieve(context.Background())
		if err != nil {
			return aws.Config{}, fmt.Errorf("unable to assume role: %w", err)
		}
	}

	credsProvider := credentials.NewStaticCredentialsProvider(creds.AccessKeyID, creds.SecretAccessKey, creds.SessionToken)
	cfg, err = config.LoadDefaultConfig(context.Background(),
		config.WithRegion("eu-west-1"),
		config.WithCredentialsProvider(credsProvider),
	)
	if err != nil {
		return aws.Config{}, fmt.Errorf("unable to create AWS config: %w", err)
	}

	// Validate that the account id in the target ARN matches the account id in the credentials.
	if req, err := sts.NewFromConfig(cfg).GetCallerIdentity(context.TODO(), &sts.GetCallerIdentityInput{}); err != nil {
		return aws.Config{}, fmt.Errorf("unable to get caller identity: %w", err)
	} else if *req.Account != parsedARN.AccountID {
		return aws.Config{}, fmt.Errorf("account id in target ARN does not match the account id in the credentials (target ARN: %s, credentials account id: %s)", parsedARN.AccountID, *req.Account)
	}
	return cfg, nil
}

type dnsRecord struct {
	name    string
	records []string
}

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
			if record.Type == "A" {
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

// getIPs retrieve the public IPs.
func (s Scanner) getIPs() ([]string, error) {
	var elasticIPs = make(map[string]string)
	// Get the public IPs from the addresses.
	paginatorAddresses := ec2.NewDescribeAddressesAttributePaginator(s.ec2Client, nil)
	for paginatorAddresses.HasMorePages() {
		resp, err := paginatorAddresses.NextPage(context.Background())
		if err != nil {
			return nil, fmt.Errorf("describe addresses: %w", err)
		}
		for _, address := range resp.Addresses {
			elasticIPs[*address.PublicIp] = *address.PublicIp
		}
	}

	// Get the public IPs from the Network Interfaces.
	paginatorNetworkInterfaces := ec2.NewDescribeNetworkInterfacesPaginator(s.ec2Client, nil)
	for paginatorNetworkInterfaces.HasMorePages() {
		resp, err := paginatorNetworkInterfaces.NextPage(context.Background())
		if err != nil {
			return nil, fmt.Errorf("describe network interfaces: %w", err)
		}
		for _, networkInterface := range resp.NetworkInterfaces {
			if networkInterface.Association != nil {
				elasticIPs[*networkInterface.Association.PublicIp] = *networkInterface.Association.PublicIp
			}
		}
	}
	return slices.Collect(maps.Keys(elasticIPs)), nil
}

func (s Scanner) calculateTakeovers(dnsRecords []dnsRecord, elasticIPs []string) ([]string, error) {
	// find all DNS records that point to EC2 IP addresses.
	var dnsEC2IPs [][]string
	aip, err := s.ipRangesClient.GetPrefixes()
	if err != nil {
		return nil, fmt.Errorf("get ip ranges: %w", err)
	}

	for _, dnsr := range dnsRecords {
		for _, record := range dnsr.records {
			awsMetadata, err := aip.GetPrefixByIP(record)
			if err != nil {
				if errors.Is(err, ErrPrefixNotFound) {
					continue
				}
				return nil, fmt.Errorf("getting AWS metadata for %s: %w", record, err)
			}
			for _, service := range strings.Split(awsMetadata.Service, ",") {
				if service == "EC2" {
					dnsEC2IPs = append(dnsEC2IPs, dnsr.records)
				}
			}
		}
	}

	var takeovers []string

	// check to see if any of the record sets we have, we don't own the elastic IPs.
	for _, dnsEC2IP := range dnsEC2IPs {
		for _, record := range dnsEC2IP {
			if !contains(elasticIPs, record) {
				takeovers = append(takeovers, record)
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
func addVulnsToState(state checkstate.State, takeovers []string, target string) {
	for _, takeover := range takeovers {
		state.AddVulnerabilities(
			report.Vulnerability{
				AffectedResource: takeover,
				Labels:           []string{"issue", "subdomain-takeover"},
				Fingerprint:      helpers.ComputeFingerprint(target, takeover),
				Summary:          `AWS Route 53 record without Elastic IP (Subdomain Takeover)`,
				Score:            report.SeverityThresholdHigh,
				Description: `The Route 53 record is pointing to an Elastic IP that is not owned by the account. ` +
					`This could lead to a subdomain takeover if the Elastic IP is released and taken by someone else.`,
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
						Header: []string{"Account", "Subdomain"},
						Rows: []map[string]string{
							{
								"Account":   target,
								"Subdomain": target,
							},
						},
					},
				},
			},
		)
	}
}
