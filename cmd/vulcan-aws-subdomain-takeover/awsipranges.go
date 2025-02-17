/*
Copyright 2025 Adevinta
*/

// Package main contains the main logic to detect subdomain takeovers.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"os"
	"slices"
	"sort"
	"strings"
)

const (
	ipRangesFile = "ip-ranges.json"
	ipRangesURL  = "https://ip-ranges.amazonaws.com/ip-ranges.json"
)

// ErrPrefixNotFound means tha a prefix wasn't found in the ip ranges.
var ErrPrefixNotFound = errors.New("prefix not found")

// AWSIPRanges contains two strings, SyncToken and CreateDate, and a slice of Prefixes.
type AWSIPRanges struct {
	SyncToken  string `json:"syncToken"`
	CreateDate string `json:"createDate"`
	d          ipRangesRetriever
	IPPrefixes []IPPrefix `json:"prefixes" json_alias:"ip6_prefixes"`
}

type ipRangesRetriever interface {
	getAWSIPRanges() (AWSIPRanges, error)
}

// IPPrefix contains four strings; IP_Prefix, Region, Service, and NetworkBorderGroup.
type IPPrefix struct {
	IPPrefix           string `json:"ip_prefix" json_alias:"ipv6_prefix"`
	Region             string `json:"region"`
	Service            string `json:"service"`
	NetworkBorderGroup string `json:"network_border_group"`
}

// AWSPrefixes represents a list of prefixes.
type AWSPrefixes struct {
	iPPrefixes []IPPrefix
}

// NewAWSIPRanges creates a new AWSIPRanges object.
func NewAWSIPRanges() *AWSIPRanges {
	if _, err := os.Stat(ipRangesFile); err == nil {
		return &AWSIPRanges{
			d: awsIPRangesFileClient{},
		}
	}
	return &AWSIPRanges{
		d: awsIPRangesURLClient{},
	}
}

// GetPrefixes returns the prefixes contained in the AWS IP Ranges file.
func (ar AWSIPRanges) GetPrefixes() (AWSPrefixes, error) {
	ranges, err := ar.d.getAWSIPRanges()
	if err != nil {
		return AWSPrefixes{}, err
	}
	prefixes, err := FromRangesToPrefixes(ranges)
	if err != nil {
		return AWSPrefixes{}, err
	}
	return *prefixes, err
}

// awsIPRangesURLClient represents a client that retrieve the IP Ranges from a file.
type awsIPRangesFileClient struct{}

// getAWSIPRanges returns the ranges contained in the AWS IP Ranges file.
func (r awsIPRangesFileClient) getAWSIPRanges() (AWSIPRanges, error) {
	jsonFile, err := os.Open(ipRangesFile)
	if err != nil {
		return AWSIPRanges{}, err
	}
	defer jsonFile.Close()

	return unmarshallRanges(jsonFile)
}

// awsIPRangesURLClient represents a client that retrieve the IP Ranges from a URL.
type awsIPRangesURLClient struct{}

// getAWSIPRanges returns the ranges contained in the AWS IP Ranges file.
func (r awsIPRangesURLClient) getAWSIPRanges() (AWSIPRanges, error) {
	client := http.DefaultClient
	res, err := client.Get(ipRangesURL)
	if err != nil {
		return AWSIPRanges{}, err
	}
	defer res.Body.Close()
	return unmarshallRanges(res.Body)
}

func unmarshallRanges(r io.Reader) (AWSIPRanges, error) {
	b, err := io.ReadAll(r)
	if err != nil {
		return AWSIPRanges{}, err
	}
	var data AWSIPRanges
	err = json.Unmarshal(b, &data)

	if err != nil {
		return AWSIPRanges{}, err
	}
	return data, nil
}

// FromRangesToPrefixes converts the AWS IP Ranges.
func FromRangesToPrefixes(ranges AWSIPRanges) (*AWSPrefixes, error) {
	prefixes, err := processIPPrefixes(ranges.IPPrefixes)
	if err != nil {
		return nil, err
	}
	return &AWSPrefixes{
		iPPrefixes: prefixes,
	}, nil
}

// processIPPrefixes takes the list of prefix and return combining the duplicated ones.
func processIPPrefixes(prefixes []IPPrefix) ([]IPPrefix, error) {
	duplicates := make(map[string][]IPPrefix)
	for _, prefix := range prefixes {
		if _, ok := duplicates[prefix.IPPrefix]; !ok {
			duplicates[prefix.IPPrefix] = []IPPrefix{}
		}
		duplicates[prefix.IPPrefix] = append(duplicates[prefix.IPPrefix], prefix)
	}

	var deduplicatedPrefixes []IPPrefix

	var prefix IPPrefix
	var err error
	for _, ipPrefixes := range duplicates {
		if len(ipPrefixes) == 1 {
			prefix = ipPrefixes[0]
		} else {
			prefix, err = combineIPPrefixes(ipPrefixes)
			if err != nil {
				return nil, err
			}
		}
		deduplicatedPrefixes = append(deduplicatedPrefixes, prefix)
	}
	return deduplicatedPrefixes, err
}

// combineIPPrefixes combines a list of prefixes.
func combineIPPrefixes(prefixes []IPPrefix) (IPPrefix, error) {
	first := prefixes[0]
	services := map[string]string{}
	services[first.Service] = first.Service
	for _, prefix := range prefixes[1:] {
		if first.IPPrefix != prefix.IPPrefix || first.Region != prefix.Region ||
			first.NetworkBorderGroup != prefix.NetworkBorderGroup {
			return IPPrefix{},
				errors.New("cannot combine prefixes with different prefix, region, or network_border_group values")
		}
		services[prefix.Service] = prefix.Service
	}
	sortedServices := slices.Collect(maps.Keys(services))
	sort.Strings(sortedServices)
	return IPPrefix{
		IPPrefix:           first.IPPrefix,
		Region:             first.Region,
		NetworkBorderGroup: first.NetworkBorderGroup,
		Service:            strings.Join(sortedServices, ","),
	}, nil
}

// GetPrefixByIP returns a [IPPrefix] given an IP.
func (ap AWSPrefixes) GetPrefixByIP(ip string) (IPPrefix, error) {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return IPPrefix{}, fmt.Errorf("invalid IP address: %s", ip)
	}
	for _, prefix := range ap.iPPrefixes {
		_, ipNet, err := net.ParseCIDR(prefix.IPPrefix)
		if err != nil {
			continue // Skip invalid CIDRs
		}
		if ipNet.Contains(parsedIP) {
			return prefix, nil
		}
	}
	return IPPrefix{}, fmt.Errorf("%w: %s", ErrPrefixNotFound, ip)
}
