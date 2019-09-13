package main

import (
	"context"
	"encoding/json"
	"strconv"
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

func exposedRouterPorts(target string, nmapReport *gonmap.NmapRun) []report.Vulnerability {
	gr := report.ResourcesGroup{
		Name: "Network Resources",
		Header: []string{
			"Hostname",
			"Port",
			"Protocol",
			"Service",
			"Version",
		},
	}

	add := false
	for _, host := range nmapReport.Hosts {
		for _, port := range host.Ports {
			if port.State.State != "open" {
				continue
			}

			add = true

			networkResource := map[string]string{
				"Hostname": target,
				"Port":     strconv.Itoa(port.PortId),
				"Protocol": port.Protocol,
				"Service":  port.Service.Product,
				"Version":  port.Service.Version,
			}
			gr.Rows = append(gr.Rows, networkResource)
		}
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
		if optJSON != "" {
			if err = json.Unmarshal([]byte(optJSON), &opt); err != nil {
				return err
			}
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

		nmapRunner := nmap.NewNmapCheck(target, state, opt.Timing, nmapParams)
		nmapReport, _, err := nmapRunner.Run(ctx)
		if err != nil {
			return err
		}

		vulns := exposedRouterPorts(target, nmapReport)
		state.AddVulnerabilities(vulns...)

		return nil
	}

	c := check.NewCheckFromHandler(checkName, run)
	c.RunAndServe()
}
