package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"

	check "github.com/adevinta/vulcan-check-sdk"
	"github.com/adevinta/vulcan-check-sdk/state"
	report "github.com/adevinta/vulcan-report"
)

var (
	checkName = "vulcan-ipv6"

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
	}
)

// IPv6Json is used for storing results from lookupAAAA
type IPv6Json struct {
	IPv6Addresses []net.IP `json:"ipv6_addresses"`
}

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

	run := func(ctx context.Context, target, targetType string, optJSON string, state state.State) (err error) {
		if net.ParseIP(target) != nil {
			return errors.New("invalid hostname provided")
		}

		ips, err := lookupAAAA(target)
		if err != nil {
			return
		}

		if len(ips) > 0 {
			state.AddVulnerabilities(IPv6IsPresent)

			ipv6JSON := &IPv6Json{
				IPv6Addresses: ips,
			}
			data, err := json.Marshal(ipv6JSON)
			if err != nil {
				return err
			}
			state.Notes = string(data)
		}

		return nil
	}
	c := check.NewCheckFromHandler(checkName, run)

	c.RunAndServe()
}
