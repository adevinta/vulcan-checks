/*
Copyright 2025 Adevinta
*/

package main

import (
	"errors"
	"net"
	"testing"

	"github.com/google/go-cmp/cmp"
)

type mockAwsIPRangesClient struct {
	retriever func() AWSIPRanges
}

func (m mockAwsIPRangesClient) getAWSIPRanges() (AWSIPRanges, error) {
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
						IPPrefix: "3.4.12.4/32",
						Service:  "EC2",
					},
					{
						IPPrefix: "3.5.140.0/22",
						Service:  "EC2",
					},
					{
						IPPrefix: "15.190.244.0/22",
						Service:  "EC2",
					},
				},
			},
			want: AWSPrefixes{
				iPPrefixes: []IPPrefix{
					{
						IPPrefix: "3.4.12.4/32",
					},
					{
						IPPrefix: "3.5.140.0/22",
					},
					{
						IPPrefix: "15.190.244.0/22",
					},
				},
			},
		},
		{
			name: "combined prefixes",
			ranges: AWSIPRanges{
				IPPrefixes: []IPPrefix{
					{
						IPPrefix: "3.4.12.4/32",
						Service:  "EC2",
					},
					{
						IPPrefix: "3.4.12.4/32",
						Service:  "AMAZON",
					},
					{
						IPPrefix: "15.190.244.0/22",
						Service:  "AMAZON",
					},
				},
			},
			want: AWSPrefixes{
				iPPrefixes: []IPPrefix{
					{
						IPPrefix: "3.4.12.4/32",
						Service:  "AMAZON,EC2",
					},
					{
						IPPrefix: "3.4.12.4/32",
						Service:  "AMAZON",
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ar := &AWSIPRanges{
				d: mockAwsIPRangesClient{
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
					IPPrefix: "3.4.12.4/32",
					Service:  "EC2",
				},
			},
			want: []IPPrefix{
				{
					IPPrefix: "3.4.12.4/32",
					ipNet:    func() *net.IPNet { _, ipNet, _ := net.ParseCIDR("3.4.12.4/32"); return ipNet }(),
				},
			},
			wantErr: false,
		},
		{
			name: "combine prefixes",
			prefixes: []IPPrefix{
				{
					IPPrefix: "3.4.12.4/32",
					Service:  "EC2",
				},
				{
					IPPrefix: "3.4.12.4/32",
					Service:  "AMAZON",
				},
			},
			want: []IPPrefix{
				{
					IPPrefix: "3.4.12.4/32",
					ipNet:    getIPNet("3.4.12.4/32"),
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := processIPPrefixes(tt.prefixes)
			opts := []cmp.Option{
				cmp.AllowUnexported(IPPrefix{}),
			}
			if diff := cmp.Diff(tt.want, got, opts...); diff != "" {
				t.Errorf("unnexpected IPPrefixes: want %v, got = %v, ", tt.want, got)
			}
		})
	}
}

func TestAWSPrefixes_GetPrefixByIP(t *testing.T) {
	iPPrefixes := []IPPrefix{
		{
			IPPrefix: "3.4.12.4/32",
			ipNet:    getIPNet("3.4.12.4/32"),
		},
		{
			IPPrefix: "3.5.140.0/22",
			ipNet:    getIPNet("3.4.12.4/32"),
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
				IPPrefix: "3.4.12.4/32",
				ipNet:    getIPNet("3.4.12.4/32"),
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
			opts := []cmp.Option{
				cmp.AllowUnexported(IPPrefix{}),
			}
			if diff := cmp.Diff(tt.want, got, opts...); diff != "" {
				t.Errorf("unnexpected IPPrefix: want %v, got = %v, ", tt.want, got)
			}
		})
	}
}

func getIPNet(prefix string) *net.IPNet {
	_, ipNet, _ := net.ParseCIDR(prefix)
	return ipNet
}
