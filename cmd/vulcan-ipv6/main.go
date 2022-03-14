/*
Copyright 2019 Adevinta
*/

package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	check "github.com/adevinta/vulcan-check-sdk"
	"github.com/adevinta/vulcan-check-sdk/helpers"
	checkstate "github.com/adevinta/vulcan-check-sdk/state"
	report "github.com/adevinta/vulcan-report"
)

var (
	checkName = "vulcan-ipv6"
	logger    = check.NewCheckLog(checkName)

	// IPv6IsPresent is a check name
	IPv6IsPresent = report.Vulnerability{
		Summary: "IPv6 presence",
		Description: "This check tests for IPv6 presence on domain names. If AAAA DNS RR is present, people should be aware of that." +
			"It also serves as a way to monitor IPv6 deployed state.",
		Score:         report.SeverityThresholdNone,
		ImpactDetails: "IPv6 is present and attacks can be carried out over IPv6 connectivity",
		Recommendations: []string{
			"Having IPv6 present is not a security vulnerability, just extra care has to be taken to also consider security services available over IPv6",
		},
		References: []string{
			"https://www.ietf.org/rfc/rfc2460.txt",
		},
		Labels:      []string{"informational", "discovery"},
		Fingerprint: helpers.ComputeFingerprint(),
	}
)

func lookupAAAA(host string) ([]net.IP, error) {
	resolvedIps, err := net.LookupIP(host)
	if err != nil {
		return nil, err
	}

	return findIPv6Addresses(resolvedIps), nil
}

func isIPv6Address(ip net.IP) bool {
	return strings.Contains(ip.String(), ":")
}

func findIPv6Addresses(resolvedIps []net.IP) []net.IP {
	var ips []net.IP

	for _, ip := range resolvedIps {
		if isIPv6Address(ip) {
			ips = append(ips, ip)
		}
	}

	return ips
}

func main() {
	run := func(ctx context.Context, target, assetType, optJSON string, state checkstate.State) (err error) {
		if net.ParseIP(target) != nil {
			return errors.New("invalid hostname provided")
		}

		isReachable, err := helpers.IsReachable(target, assetType, nil)
		if err != nil {
			logger.Warnf("Can not check asset reachability: %v", err)
		}
		if !isReachable {
			return checkstate.ErrAssetUnreachable
		}

		ips, err := lookupAAAA(target)
		if err != nil {
			return
		}

		if len(ips) > 0 {
			gr := report.ResourcesGroup{
				Name: "IPv6 Addresses",
				Header: []string{
					"Address",
				},
			}
			for _, ip := range ips {
				row := map[string]string{
					"Address": fmt.Sprintf("%s", ip),
				}
				gr.Rows = append(gr.Rows, row)
			}
			vuln := IPv6IsPresent
			vuln.AffectedResource = target
			vuln.Resources = []report.ResourcesGroup{gr}
			state.AddVulnerabilities(vuln)
		}

		return nil
	}
	c := check.NewCheckFromHandler(checkName, run)

	c.RunAndServe()
}
