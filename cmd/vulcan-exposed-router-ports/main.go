/*
Copyright 2019 Adevinta
*/

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	gonmap "github.com/lair-framework/go-nmap"

	check "github.com/adevinta/vulcan-check-sdk"
	"github.com/adevinta/vulcan-check-sdk/helpers"
	"github.com/adevinta/vulcan-check-sdk/helpers/nmap"
	checkstate "github.com/adevinta/vulcan-check-sdk/state"
	report "github.com/adevinta/vulcan-report"
)

type options struct {
	// Nmap timing parameter.
	Timing int `json:"timing"`
	// Return status updates on the progress of the check
	ReportProgress bool `json:"report_progress"`
	// List of potential database ports to scan for.
	Ports []string `json:"ports"`
}

var (
	checkName = "vulcan-exposed-router-ports"

	defaultTiming = 3
	defaultPorts  = []string{
		"T:20-21",   // FTP
		"T:22",      // SSH
		"T:23",      // Telnet
		"U:53",      // DNS
		"T:53",      // DNS
		"U:69",      // TFTP
		"T:80",      // HTTP
		"U:161",     // SNMP
		"T:443",     // HTTPS
		"T:830-833", // NETCONF
		"T:8080",    // HTTP
	}

	exposedVuln = report.Vulnerability{
		Summary:       "Exposed Router Ports",
		Description:   "At least one port of the router is accessible from the public Internet.",
		Score:         report.SeverityThresholdNone,
		ImpactDetails: "An attacker may be able to remotely connect to the network device through the exposed port.",
		Recommendations: []string{
			"Restrict access to the network devices admin ports from the Internet",
		},
		References: []string{
			"https://tools.ietf.org/html/rfc4778",
		},
	}
)

func exposedRouterPorts(target string, nmapReport *gonmap.NmapRun, state checkstate.State) {
	for _, host := range nmapReport.Hosts {
		for _, port := range host.Ports {
			if port.State.State != "open" {
				continue
			}
			vuln := exposedVuln
			vuln.AffectedResource = fmt.Sprintf("%d/%s", port.PortId, port.Protocol)
			vuln.Fingerprint = helpers.ComputeFingerprint(port.Service.Product)
			vuln.Labels = []string{"issue", "discovery"}
			vuln.Resources = []report.ResourcesGroup{{
				Name: "Network Resources",
				Header: []string{
					"Hostname",
					"Port",
					"Protocol",
					"Service",
					"Version",
				},
				Rows: []map[string]string{{
					"Hostname": target,
					"Port":     strconv.Itoa(port.PortId),
					"Protocol": port.Protocol,
					"Service":  port.Service.Product,
					"Version":  port.Service.Version,
				}},
			}}
			state.AddVulnerabilities(vuln)
		}
	}
}

func main() {
	run := func(ctx context.Context, target, assetType, optJSON string, state checkstate.State) (err error) {
		logger := check.NewCheckLogFromContext(ctx, checkName)
		var opt options
		if optJSON != "" {
			if err = json.Unmarshal([]byte(optJSON), &opt); err != nil {
				return err
			}
		}

		isReachable, err := helpers.IsReachable(target, assetType, nil)
		if err != nil {
			logger.Warnf("Can not check asset reachability: %v", err)
		}
		if !isReachable {
			return checkstate.ErrAssetUnreachable
		}

		if opt.Timing == 0 {
			opt.Timing = defaultTiming
		}

		if len(opt.Ports) == 0 {
			opt.Ports = defaultPorts
		}

		// Scan with version detection.
		nmapParams := map[string]string{
			"-Pn": "",
			"-sV": "",
			"-sU": "",
			"-sT": "",
			"-p":  strings.Join(opt.Ports, ","),
		}

		nmapRunner := nmap.NewNmapCheck(target, state, opt.Timing, opt.ReportProgress, nmapParams)
		nmapReport, _, err := nmapRunner.Run(ctx)
		if err != nil {
			return err
		}

		exposedRouterPorts(target, nmapReport, state)

		return nil
	}

	c := check.NewCheckFromHandler(checkName, run)
	c.RunAndServe()
}
