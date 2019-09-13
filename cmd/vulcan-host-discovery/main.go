package main

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strings"

	gonmap "github.com/lair-framework/go-nmap"

	"github.com/adevinta/vulcan-check-sdk"
	"github.com/adevinta/vulcan-check-sdk/helpers/nmap"
	"github.com/adevinta/vulcan-check-sdk/state"
	"github.com/adevinta/vulcan-report"
)

type options struct {
	// Nmap timing parameter.
	Timing int `json:"timing"`

	/***
	 * If a list of known hosts is provided, the check will return results only when
	 * a scanned host that has been found to be up is not in the list of known hosts.
	 *
	 * If no known hosts are provided, all the hosts that were found to be up will
	 * be reported.
	 *
	 * Note that you must provide a URL with a parsable json list of known hosts
	 * that looks like this:
	 *
	 *     [
	 *         "knownhost1.example.com",
	 *         "192.168.0.1"
	 *     ]
	 */
	KnownHostsListURL string `json:"known_hosts_list_url"`
}

var (
	checkName = "vulcan-host-discovery"

	defaultTiming = 3

	exposedVuln = report.Vulnerability{
		Summary:       "Unknown Hosts",
		Description:   "At least one unknown host has been discovered in the network.",
		Score:         report.SeverityThresholdMedium,
		ImpactDetails: "Unknown hosts can be unauthorized malicious hosts",
		Recommendations: []string{
			"If you cannot identify a discovered host, it can be an unauthorized and potentially malicious host.",
			"If you can identify a discovered host as a legitimate active host, you should add the host to the list of known hosts.",
			"If you can identify a discovered host as a previously known host that is not in use anymore, you should consider decommissioning it.",
		},
	}
)

func isHostInKnownHosts(host string, knownHosts []string) bool {
	for _, knownHost := range knownHosts {
		if host == knownHost {
			return true
		}
	}

	return false
}

func discoveredHosts(targetSubnet string, knownHosts []string, nmapReport *gonmap.NmapRun) []report.Vulnerability {
	gr := report.ResourcesGroup{
		Name: "Network Resources",
		Header: []string{
			"Subnet",
			"IP Address",
			"Hostname",
		},
	}

	/***
	 * If a list of known hosts hasn't been provided, this is just an informational report.
	 * Therefore, reduce the vulnerability score to SeverityThresholdNone and change the
	 * summary to "Discovered Hosts" instead of "Unknown Hosts".
	 */
	if len(knownHosts) == 0 {
		exposedVuln.Summary = "Discovered Hosts"
		exposedVuln.Description = "At least one host has been discovered in the network"
		exposedVuln.Recommendations = []string{
			"Identify that all of the discovered hosts are known hosts",
		}
		exposedVuln.Score = report.SeverityThresholdNone
		exposedVuln.ImpactDetails = "If any of the discovered hosts is not known, it may be an unauthorized malicious host."
	}

	add := false

nmapReportLoop:
	for _, host := range nmapReport.Hosts {
		if host.Status.State != "up" {
			// We do not care about hosts that are not up. This is not a monitoring tool.
			continue
		}

		var hostIPAddresses []string
		var hostHostnames []string

		for _, address := range host.Addresses {
			/***
			 * If the IP address is in the list of known hosts continue processing the next host.
			 * Do not add known hosts in the results.
			 */
			if isHostInKnownHosts(address.Addr, knownHosts) {
				continue nmapReportLoop
			}

			hostIPAddresses = append(hostIPAddresses, address.Addr)
		}

		for _, hostname := range host.Hostnames {
			/***
			 * If the domain name is in the list of known hosts continue processing the next host.
			 * Do not add known hosts in the results.
			 */
			if isHostInKnownHosts(hostname.Name, knownHosts) {
				continue nmapReportLoop
			}

			hostHostnames = append(hostHostnames, hostname.Name)
		}

		// At this point the host is not in the list of known hosts, so add the host to the results.
		add = true

		networkResource := map[string]string{
			"Subnet":     targetSubnet,
			"IP Address": strings.Join(hostIPAddresses, ","),
			"Hostname":   strings.Join(hostHostnames, ","),
		}
		gr.Rows = append(gr.Rows, networkResource)
	}

	if add {
		exposedVuln.Resources = append(exposedVuln.Resources, gr)
		return []report.Vulnerability{exposedVuln}
	}

	return nil
}

func main() {
	run := func(ctx context.Context, target string, optJSON string, state state.State) (err error) {
		var opt options
		var knownHosts []string

		if optJSON != "" {
			if err = json.Unmarshal([]byte(optJSON), &opt); err != nil {
				return err
			}
		}

		if opt.Timing == 0 {
			opt.Timing = defaultTiming
		}

		// Read known hosts from KnownHostsListURL if provided
		if opt.KnownHostsListURL != "" {
			resp, err := http.Get(opt.KnownHostsListURL)
			if err != nil {
				return err
			}

			defer resp.Body.Close()
			knownHostsJSON, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				return err
			}

			if err = json.Unmarshal(knownHostsJSON, &knownHosts); err != nil {
				return err
			}
		}

		// Perform a quick host discovery (or ping scan in nmap terminology)
		nmapParams := map[string]string{
			"-sn": "",
		}

		// Ideally, the target should be a subnet mask, but /32 address will also work.
		nmapRunner := nmap.NewNmapCheck(target, state, opt.Timing, nmapParams)
		nmapReport, _, err := nmapRunner.Run(ctx)
		if err != nil {
			return err
		}

		unknownHosts := discoveredHosts(target, knownHosts, nmapReport)
		state.AddVulnerabilities(unknownHosts...)

		return nil
	}

	c := check.NewCheckFromHandler(checkName, run)
	c.RunAndServe()
}
