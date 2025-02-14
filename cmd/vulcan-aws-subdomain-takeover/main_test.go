package main

import (
	"context"
	"sort"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	typesec2 "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	typesroute53 "github.com/aws/aws-sdk-go-v2/service/route53/types"
	"github.com/google/go-cmp/cmp"
)

type mockedRoute53API struct {
	listHostedZonesOutput        []route53.ListHostedZonesOutput
	hostedZonesCallCount         int
	listResourceRecordSetsOutput []route53.ListResourceRecordSetsOutput
	resourceRecordSetCallCount   int
}

func (mr *mockedRoute53API) ListHostedZones(
	_ context.Context, _ *route53.ListHostedZonesInput, _ ...func(*route53.Options)) (*route53.ListHostedZonesOutput, error) {
	result := &mr.listHostedZonesOutput[mr.hostedZonesCallCount]
	mr.hostedZonesCallCount++
	return result, nil
}

func (mr *mockedRoute53API) ListResourceRecordSets(
	_ context.Context, _ *route53.ListResourceRecordSetsInput, _ ...func(*route53.Options)) (*route53.ListResourceRecordSetsOutput, error) {
	result := &mr.listResourceRecordSetsOutput[mr.resourceRecordSetCallCount]
	mr.resourceRecordSetCallCount++
	return result, nil
}

func TestScanner_getRoute53ARecords(t *testing.T) {
	tests := []struct {
		name                         string
		listHostedZonesOutput        []route53.ListHostedZonesOutput
		listResourceRecordSetsOutput []route53.ListResourceRecordSetsOutput
		want                         []dnsRecord
		wantErr                      bool
	}{
		{
			name: "no hosted zones",
			listHostedZonesOutput: []route53.ListHostedZonesOutput{
				{},
			},
			listResourceRecordSetsOutput: []route53.ListResourceRecordSetsOutput{
				{},
			},
			want:    nil,
			wantErr: false,
		},
		{
			name: "hosted zones with no records",
			listHostedZonesOutput: []route53.ListHostedZonesOutput{
				{
					HostedZones: []typesroute53.HostedZone{
						{
							Id: ptr("HostedZone1"),
						},
					},
				},
			},
			listResourceRecordSetsOutput: []route53.ListResourceRecordSetsOutput{
				{},
			},
			want:    nil,
			wantErr: false,
		},
		{
			name: "hosted zones with A record",
			listHostedZonesOutput: []route53.ListHostedZonesOutput{
				{
					HostedZones: []typesroute53.HostedZone{
						{
							Id: ptr("HostedZone1"),
						},
					},
				},
			},
			listResourceRecordSetsOutput: []route53.ListResourceRecordSetsOutput{
				{
					ResourceRecordSets: []typesroute53.ResourceRecordSet{
						{
							Type: typesroute53.RRTypeA,
							ResourceRecords: []typesroute53.ResourceRecord{
								{
									Value: ptr("ResourceRecordAValue"),
								},
							},
							Name: ptr("ResourceRecordA"),
						},
					},
				},
			},
			want: []dnsRecord{
				{
					name:    "ResourceRecordA",
					records: []string{"ResourceRecordAValue"},
				},
			},
			wantErr: false,
		},
		{
			name: "hosted zones without A record",
			listHostedZonesOutput: []route53.ListHostedZonesOutput{
				{
					HostedZones: []typesroute53.HostedZone{
						{
							Id: ptr("HostedZone1"),
						},
					},
				},
			},
			listResourceRecordSetsOutput: []route53.ListResourceRecordSetsOutput{
				{
					ResourceRecordSets: []typesroute53.ResourceRecordSet{
						{
							Type: typesroute53.RRTypeDs,
							ResourceRecords: []typesroute53.ResourceRecord{
								{
									Value: ptr("ResourceRecordDsValue"),
								},
							},
							Name: ptr("ResourceRecordDs"),
						},
					},
				},
			},
			want:    nil,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := Scanner{
				route53Client: &mockedRoute53API{
					listHostedZonesOutput:        tt.listHostedZonesOutput,
					listResourceRecordSetsOutput: tt.listResourceRecordSetsOutput,
				},
			}
			got, err := s.getRoute53ARecords()
			if (err != nil) != tt.wantErr {
				t.Errorf("unexpected error value: %v", err)
			}
			opts := []cmp.Option{
				cmp.AllowUnexported(dnsRecord{}),
			}
			if diff := cmp.Diff(tt.want, got, opts...); diff != "" {
				t.Errorf("unnexpected HostedZones: want %v, got = %v", tt.want, got)
			}
		})
	}
}

func TestScanner_getRoute53HostedZones(t *testing.T) {
	tests := []struct {
		name                  string
		listHostedZonesOutput []route53.ListHostedZonesOutput
		want                  []typesroute53.HostedZone
		wantErr               bool
	}{
		{
			name: "no hosted zones",
			listHostedZonesOutput: []route53.ListHostedZonesOutput{
				{
					HostedZones: []typesroute53.HostedZone{},
				},
			},
			want:    nil,
			wantErr: false,
		},
		{
			name: "one hosted zone",
			listHostedZonesOutput: []route53.ListHostedZonesOutput{
				{
					HostedZones: []typesroute53.HostedZone{
						{
							Id: ptr("HostedZone1"),
						},
					},
				},
			},
			want: []typesroute53.HostedZone{
				{
					Id: ptr("HostedZone1"),
				},
			},
			wantErr: false,
		},
		{
			name: "paginated hosted zones",
			listHostedZonesOutput: []route53.ListHostedZonesOutput{
				{
					HostedZones: []typesroute53.HostedZone{
						{
							Id: ptr("HostedZone1"),
						},
					},
					IsTruncated: true,
					NextMarker:  ptr("NextMarker"),
				},
				{
					HostedZones: []typesroute53.HostedZone{
						{
							Id: ptr("HostedZone2"),
						},
					},
					IsTruncated: false,
				},
			},
			want: []typesroute53.HostedZone{
				{
					Id: ptr("HostedZone1"),
				},
				{
					Id: ptr("HostedZone2"),
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := Scanner{
				route53Client: &mockedRoute53API{
					listHostedZonesOutput: tt.listHostedZonesOutput,
				},
			}
			got, err := s.getRoute53HostedZones()
			if (err != nil) != tt.wantErr {
				t.Errorf("unexpected error value: %v", err)
			}
			opts := []cmp.Option{
				cmp.AllowUnexported(typesroute53.HostedZone{}),
			}
			if diff := cmp.Diff(tt.want, got, opts...); diff != "" {
				t.Errorf("unnexpected HostedZones: want %v, got = %v", tt.want, got)
			}
		})
	}
}

func TestScanner_getRoute53ZoneRecords(t *testing.T) {
	tests := []struct {
		name                         string
		listResourceRecordSetsOutput []route53.ListResourceRecordSetsOutput
		want                         []typesroute53.ResourceRecordSet
		wantErr                      bool
	}{
		{
			name: "no zone records",
			listResourceRecordSetsOutput: []route53.ListResourceRecordSetsOutput{
				{
					ResourceRecordSets: []typesroute53.ResourceRecordSet{},
				},
			},
			want:    nil,
			wantErr: false,
		},
		{
			name: "a zone record",
			listResourceRecordSetsOutput: []route53.ListResourceRecordSetsOutput{
				{
					ResourceRecordSets: []typesroute53.ResourceRecordSet{
						{
							Type: typesroute53.RRTypeA,
							ResourceRecords: []typesroute53.ResourceRecord{
								{
									Value: ptr("ResourceRecordA"),
								},
							},
						},
					},
				},
			},
			want: []typesroute53.ResourceRecordSet{
				{
					Type: typesroute53.RRTypeA,
					ResourceRecords: []typesroute53.ResourceRecord{
						{
							Value: ptr("ResourceRecordA"),
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "paginated zone records",
			listResourceRecordSetsOutput: []route53.ListResourceRecordSetsOutput{
				{
					ResourceRecordSets: []typesroute53.ResourceRecordSet{
						{
							Type: typesroute53.RRTypeA,
							ResourceRecords: []typesroute53.ResourceRecord{
								{
									Value: ptr("ResourceRecordA"),
								},
							},
						},
					},
					NextRecordName: ptr("ResourceRecordA2"),
					NextRecordType: typesroute53.RRTypeA,
					IsTruncated:    true,
				},
				{
					ResourceRecordSets: []typesroute53.ResourceRecordSet{
						{
							Type: typesroute53.RRTypeA,
							ResourceRecords: []typesroute53.ResourceRecord{
								{
									Value: ptr("ResourceRecordA2"),
								},
							},
						},
					},
					IsTruncated: false,
				},
			},
			want: []typesroute53.ResourceRecordSet{
				{
					Type: typesroute53.RRTypeA,
					ResourceRecords: []typesroute53.ResourceRecord{
						{
							Value: ptr("ResourceRecordA"),
						},
					},
				},
				{
					Type: typesroute53.RRTypeA,
					ResourceRecords: []typesroute53.ResourceRecord{
						{
							Value: ptr("ResourceRecordA2"),
						},
					},
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := Scanner{
				route53Client: &mockedRoute53API{
					listResourceRecordSetsOutput: tt.listResourceRecordSetsOutput,
				},
			}
			got, err := s.getRoute53ZoneRecords(nil)
			if (err != nil) != tt.wantErr {
				t.Errorf("unexpected error value: %v", err)
			}
			opts := []cmp.Option{
				cmp.AllowUnexported(typesroute53.ResourceRecord{}, typesroute53.ResourceRecordSet{}),
			}
			if diff := cmp.Diff(tt.want, got, opts...); diff != "" {
				t.Errorf("unnexpected ResourceRecordSet: want %v, got = %v", tt.want, got)
			}
		})
	}
}

type mockedEC2Client struct {
	describeRegionsOutput            []ec2.DescribeRegionsOutput
	describeRegionsCount             int
	describeAddressesAttributeOutput []ec2.DescribeAddressesAttributeOutput
	describeAddressAttributeCount    int
	describeNetworkInterfacesOutput  []ec2.DescribeNetworkInterfacesOutput
	describeNetworkInterfacesCount   int
}

func (me *mockedEC2Client) DescribeRegions(_ context.Context, _ *ec2.DescribeRegionsInput, _ ...func(*ec2.Options)) (*ec2.DescribeRegionsOutput, error) {
	result := &me.describeRegionsOutput[me.describeRegionsCount]
	me.describeRegionsCount++
	return result, nil
}

func (me *mockedEC2Client) DescribeAddressesAttribute(
	_ context.Context, _ *ec2.DescribeAddressesAttributeInput, _ ...func(*ec2.Options)) (*ec2.DescribeAddressesAttributeOutput, error) {
	result := &me.describeAddressesAttributeOutput[me.describeAddressAttributeCount]
	me.describeAddressAttributeCount++
	return result, nil
}

func (me *mockedEC2Client) DescribeNetworkInterfaces(
	_ context.Context, _ *ec2.DescribeNetworkInterfacesInput, _ ...func(*ec2.Options)) (*ec2.DescribeNetworkInterfacesOutput, error) {
	result := &me.describeNetworkInterfacesOutput[me.describeNetworkInterfacesCount]
	me.describeNetworkInterfacesCount++
	return result, nil
}

func TestScanner_getIPs(t *testing.T) {
	tests := []struct {
		name                             string
		regions                          []string
		describeAddressesAttributeOutput []ec2.DescribeAddressesAttributeOutput
		describeNetworkInterfacesOutput  []ec2.DescribeNetworkInterfacesOutput
		want                             []string
		wantErr                          bool
	}{
		{
			name:                             "no addresses",
			regions:                          []string{},
			describeAddressesAttributeOutput: []ec2.DescribeAddressesAttributeOutput{{}},
			describeNetworkInterfacesOutput:  []ec2.DescribeNetworkInterfacesOutput{{}},
			want:                             nil,
			wantErr:                          false,
		},
		{
			name:    "an IP address",
			regions: []string{"us-east-1"},
			describeAddressesAttributeOutput: []ec2.DescribeAddressesAttributeOutput{
				{
					Addresses: []typesec2.AddressAttribute{
						{
							PublicIp: ptr("1.2.3.4"),
						},
					},
				},
			},
			describeNetworkInterfacesOutput: []ec2.DescribeNetworkInterfacesOutput{
				{
					NetworkInterfaces: []typesec2.NetworkInterface{
						{
							Association: &typesec2.NetworkInterfaceAssociation{
								PublicIp: ptr("1.2.3.5"),
							},
						},
					},
				},
			},
			want:    []string{"1.2.3.4", "1.2.3.5"},
			wantErr: false,
		},
		{
			name:    "paginated IP addresses",
			regions: []string{"us-east-1"},
			describeAddressesAttributeOutput: []ec2.DescribeAddressesAttributeOutput{
				{
					Addresses: []typesec2.AddressAttribute{
						{
							PublicIp: ptr("1.2.3.4"),
						},
					},
					NextToken: ptr("NextToken"),
				},
				{
					Addresses: []typesec2.AddressAttribute{
						{
							PublicIp: ptr("1.2.3.5"),
						},
					},
				},
			},
			describeNetworkInterfacesOutput: []ec2.DescribeNetworkInterfacesOutput{
				{
					NetworkInterfaces: []typesec2.NetworkInterface{
						{
							Association: &typesec2.NetworkInterfaceAssociation{
								PublicIp: ptr("1.2.3.6"),
							},
						},
					},
					NextToken: ptr("NextToken"),
				},
				{
					NetworkInterfaces: []typesec2.NetworkInterface{
						{
							Association: &typesec2.NetworkInterfaceAssociation{
								PublicIp: ptr("1.2.3.7"),
							},
						},
					},
				},
			},
			want:    []string{"1.2.3.4", "1.2.3.5", "1.2.3.6", "1.2.3.7"},
			wantErr: false,
		},
		{
			name:    "paginated IP addresses in more than a region",
			regions: []string{"us-east-1", "us-east-2"},
			describeAddressesAttributeOutput: []ec2.DescribeAddressesAttributeOutput{
				{
					Addresses: []typesec2.AddressAttribute{
						{
							PublicIp: ptr("1.2.3.4"),
						},
					},
					NextToken: ptr("NextToken"),
				},
				{
					Addresses: []typesec2.AddressAttribute{
						{
							PublicIp: ptr("1.2.3.5"),
						},
					},
				},
				{
					Addresses: []typesec2.AddressAttribute{
						{
							PublicIp: ptr("1.2.3.6"),
						},
					},
					NextToken: ptr("NextToken"),
				},
				{
					Addresses: []typesec2.AddressAttribute{
						{
							PublicIp: ptr("1.2.3.7"),
						},
					},
				},
			},
			describeNetworkInterfacesOutput: []ec2.DescribeNetworkInterfacesOutput{
				{
					NetworkInterfaces: []typesec2.NetworkInterface{
						{
							Association: &typesec2.NetworkInterfaceAssociation{
								PublicIp: ptr("1.2.3.6"),
							},
						},
					},
					NextToken: ptr("NextToken"),
				},
				{
					NetworkInterfaces: []typesec2.NetworkInterface{
						{
							Association: &typesec2.NetworkInterfaceAssociation{
								PublicIp: ptr("1.2.3.7"),
							},
						},
					},
				},
				{
					NetworkInterfaces: []typesec2.NetworkInterface{},
					NextToken:         nil,
				},
			},
			want:    []string{"1.2.3.4", "1.2.3.5", "1.2.3.6", "1.2.3.7"},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := Scanner{
				ec2Client: &mockedEC2Client{
					describeAddressesAttributeOutput: tt.describeAddressesAttributeOutput,
					describeNetworkInterfacesOutput:  tt.describeNetworkInterfacesOutput,
				},
			}
			got, err := s.getIPs(tt.regions)
			if (err != nil) != tt.wantErr {
				t.Errorf("unexpected error value: %v", err)
			}
			sort.Strings(tt.want)
			sort.Strings(got)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("unnexpected IP: want %v, got = %v", tt.want, got)
			}
		})
	}
}

type mockedCloudInventory struct {
	publicIPs []string
}

func (m mockedCloudInventory) IsIPPublicInInventory(ip string) (bool, error) {
	for _, publicIP := range m.publicIPs {
		if publicIP == ip {
			return true, nil
		}
	}
	return false, nil
}

type mockedIpRangesClient struct {
	awsPrefixes AWSPrefixes
}

func (mi mockedIpRangesClient) GetPrefixes() (AWSPrefixes, error) {
	return mi.awsPrefixes, nil
}

func TestScanner_calculateTakeovers(t *testing.T) {
	publicIPs := []string{"1.2.3.4", "1.2.3.5", "1.2.3.6", "1.2.3.7"}
	tests := []struct {
		name        string
		elasticIPs  []string
		dnsRecords  []dnsRecord
		awsPrefixes AWSPrefixes
		global      bool
		want        map[string]string
		wantErr     bool
	}{
		{
			name:        "no takeovers",
			elasticIPs:  nil,
			dnsRecords:  nil,
			awsPrefixes: AWSPrefixes{},
			global:      false,
			want:        map[string]string{},
			wantErr:     false,
		},
		{
			name: "no takeover global",
			dnsRecords: []dnsRecord{
				{
					name: "dnsRecord1.example.com",
					records: []string{
						"1.2.3.5",
					},
				},
			},
			awsPrefixes: AWSPrefixes{
				iPPrefixes: []IPPrefix{
					{
						IPPrefix:           "1.2.3.5/32",
						Region:             "eu-west-1",
						Service:            "EC2",
						NetworkBorderGroup: "eu-west-1",
					},
				},
			},
			global:  true,
			want:    map[string]string{},
			wantErr: false,
		},
		{
			name: "takeover",
			dnsRecords: []dnsRecord{
				{
					name: "dnsRecord1.example.com",
					records: []string{
						"1.2.3.5",
					},
				},
			},
			awsPrefixes: AWSPrefixes{
				iPPrefixes: []IPPrefix{
					{
						IPPrefix:           "1.2.3.5/32",
						Region:             "eu-west-1",
						Service:            "EC2",
						NetworkBorderGroup: "eu-west-1",
					},
				},
			},
			global: false,
			want: map[string]string{
				"dnsRecord1.example.com": "1.2.3.5",
			},
			wantErr: false,
		},
		{
			name: "takeover global",
			dnsRecords: []dnsRecord{
				{
					name: "dnsRecord1.example.com",
					records: []string{
						"1.2.3.8",
					},
				},
			},
			awsPrefixes: AWSPrefixes{
				iPPrefixes: []IPPrefix{
					{
						IPPrefix:           "1.2.3.8/32",
						Region:             "eu-west-1",
						Service:            "EC2",
						NetworkBorderGroup: "eu-west-1",
					},
				},
			},
			global: true,
			want: map[string]string{
				"dnsRecord1.example.com": "1.2.3.8",
			},
			wantErr: false,
		},
		{
			name:       "prefix not found",
			elasticIPs: nil,
			dnsRecords: []dnsRecord{
				{
					name: "dnsRecord1.example.com",
					records: []string{
						"1.2.3.5",
					},
				},
			},
			awsPrefixes: AWSPrefixes{
				iPPrefixes: []IPPrefix{
					{
						IPPrefix:           "1.2.3.4/32",
						Region:             "eu-west-1",
						Service:            "EC2",
						NetworkBorderGroup: "eu-west-1",
					},
				},
			},
			global:  false,
			want:    map[string]string{},
			wantErr: false,
		},
		{
			name:       "dns pointing to a existing ip",
			elasticIPs: []string{"1.2.3.4"},
			dnsRecords: []dnsRecord{
				{
					name: "dnsRecord1.example.com",
					records: []string{
						"1.2.3.4",
					},
				},
			},
			awsPrefixes: AWSPrefixes{
				iPPrefixes: []IPPrefix{
					{
						IPPrefix:           "1.2.3.4/32",
						Region:             "eu-west-1",
						Service:            "EC2",
						NetworkBorderGroup: "eu-west-1",
					},
				},
			},
			global:  false,
			want:    map[string]string{},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := Scanner{
				global: tt.global,
				inventory: &mockedCloudInventory{
					publicIPs: publicIPs,
				},
				ipRangesClient: &mockedIpRangesClient{
					awsPrefixes: tt.awsPrefixes,
				},
			}
			got, err := s.calculateTakeovers(tt.dnsRecords, tt.elasticIPs)
			if (err != nil) != tt.wantErr {
				t.Errorf("unexpected error value: %v", err)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("unnexpected IP: want %v, got = %v", tt.want, got)
			}
		})
	}
}

func ptr[V any](v V) *V {
	return &v
}
