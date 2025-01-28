/*
Copyright 2025 Adevinta
*/

package main

import (
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
)

type mockAwsIpRangesClient struct {
	retriever func() AWSIPRanges
}

func (m mockAwsIpRangesClient) getAWSIPRanges() (AWSIPRanges, error) {
	return m.retriever(), nil
}

func TestAWSIPRanges_GetPrefixes(t *testing.T) {
	tests := []struct {
		name    string
		ranges  AWSIPRanges
		want    AWSPrefixes
		wantErr bool
	}{
		{
			name: "happy path",
			ranges: AWSIPRanges{
				IPPrefixes: []IPPrefix{
					{
						IPPrefix:           "3.4.12.4/32",
						Region:             "eu-west-1",
						Service:            "AMAZON",
						NetworkBorderGroup: "eu-west-1",
					},
					{
						IPPrefix:           "3.5.140.0/22",
						Region:             "ap-northeast-2",
						Service:            "AMAZON",
						NetworkBorderGroup: "ap-northeast-2",
					},
					{
						IPPrefix:           "15.190.244.0/22",
						Region:             "ap-east-2",
						Service:            "AMAZON",
						NetworkBorderGroup: "ap-east-2",
					},
				},
			},
			want: AWSPrefixes{
				iPPrefixes: []IPPrefix{
					{
						IPPrefix:           "3.4.12.4/32",
						Region:             "eu-west-1",
						Service:            "AMAZON",
						NetworkBorderGroup: "eu-west-1",
					},
					{
						IPPrefix:           "3.5.140.0/22",
						Region:             "ap-northeast-2",
						Service:            "AMAZON",
						NetworkBorderGroup: "ap-northeast-2",
					},
					{
						IPPrefix:           "15.190.244.0/22",
						Region:             "ap-east-2",
						Service:            "AMAZON",
						NetworkBorderGroup: "ap-east-2",
					},
				},
			},
		},
		{
			name: "combined prefixes",
			ranges: AWSIPRanges{
				IPPrefixes: []IPPrefix{
					{
						IPPrefix:           "3.4.12.4/32",
						Region:             "us-east-1",
						Service:            "EC2",
						NetworkBorderGroup: "NBG",
					},
					{
						IPPrefix:           "3.4.12.4/32",
						Region:             "us-east-1",
						Service:            "AMAZON",
						NetworkBorderGroup: "NBG",
					},
					{
						IPPrefix:           "15.190.244.0/22",
						Region:             "ap-east-2",
						Service:            "AMAZON",
						NetworkBorderGroup: "ap-east-2",
					},
				},
			},
			want: AWSPrefixes{
				iPPrefixes: []IPPrefix{
					{
						IPPrefix:           "3.4.12.4/32",
						Region:             "us-east-1",
						Service:            "AMAZON,EC2",
						NetworkBorderGroup: "NBG",
					},
					{
						IPPrefix:           "3.4.12.4/32",
						Region:             "us-east-1",
						Service:            "AMAZON",
						NetworkBorderGroup: "NBG",
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			ar := &AWSIPRanges{
				d: mockAwsIpRangesClient{
					retriever: func() AWSIPRanges {
						return tt.ranges
					},
				},
			}
			prefixes, err := ar.GetPrefixes()
			if err != nil {
				t.Errorf("Error getting prefixes: %v", err)
			}

			if len(prefixes.iPPrefixes) == 0 {
				t.Errorf("Error getting prefixes: %v", err)
			}
		})
	}
}

func TestProcessIPPrefixes(t *testing.T) {
	tests := []struct {
		name     string
		prefixes []IPPrefix
		want     []IPPrefix
		wantErr  bool
	}{
		{
			name:     "no prefixes",
			prefixes: []IPPrefix{},
			want:     nil,
			wantErr:  false,
		},
		{
			name: "single prefix",
			prefixes: []IPPrefix{
				{
					IPPrefix:           "3.4.12.4/32",
					Region:             "us-east-1",
					Service:            "EC2",
					NetworkBorderGroup: "NBG",
				},
			},
			want: []IPPrefix{
				{
					IPPrefix:           "3.4.12.4/32",
					Region:             "us-east-1",
					Service:            "EC2",
					NetworkBorderGroup: "NBG",
				},
			},
			wantErr: false,
		},
		{
			name: "combine prefixes",
			prefixes: []IPPrefix{
				{
					IPPrefix:           "3.4.12.4/32",
					Region:             "us-east-1",
					Service:            "EC2",
					NetworkBorderGroup: "NBG",
				},
				{
					IPPrefix:           "3.4.12.4/32",
					Region:             "us-east-1",
					Service:            "AMAZON",
					NetworkBorderGroup: "NBG",
				},
			},
			want: []IPPrefix{
				{
					IPPrefix:           "3.4.12.4/32",
					Region:             "us-east-1",
					Service:            "AMAZON,EC2",
					NetworkBorderGroup: "NBG",
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := processIPPrefixes(tt.prefixes)
			if (err != nil) != tt.wantErr {
				t.Errorf("unexpected error value: %v", err)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("unnexpected IPPrefixes: want %v, got = %v, ", tt.want, got)
			}
		})
	}
}

func TestAWSPrefixes_GetPrefixByIP(t *testing.T) {
	iPPrefixes := []IPPrefix{
		{
			IPPrefix:           "3.4.12.4/32",
			Region:             "eu-west-1",
			Service:            "AMAZON",
			NetworkBorderGroup: "eu-west-1",
		},
		{
			IPPrefix:           "3.5.140.0/22",
			Region:             "ap-northeast-2",
			Service:            "AMAZON",
			NetworkBorderGroup: "ap-northeast-2",
		},
	}

	tests := []struct {
		name    string
		ip      string
		want    IPPrefix
		wantErr error
	}{
		{
			name: "existing prefix",
			ip:   "3.4.12.4",
			want: IPPrefix{
				IPPrefix:           "3.4.12.4/32",
				Region:             "eu-west-1",
				Service:            "AMAZON",
				NetworkBorderGroup: "eu-west-1",
			},
			wantErr: nil,
		},
		{
			name:    "non existing prefix",
			ip:      "3.4.12.5",
			want:    IPPrefix{},
			wantErr: ErrPrefixNotFound,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			awsPrefixes := &AWSPrefixes{
				iPPrefixes: iPPrefixes,
			}
			got, err := awsPrefixes.GetPrefixByIP(tt.ip)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("unexpected error value: %v", err)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("unnexpected IPPrefix: want %v, got = %v, ", tt.want, got)
			}
		})
	}
}
