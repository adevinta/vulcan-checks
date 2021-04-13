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

	/* Lists of whitelisted TCP and UDP ports.
	 *
	 * Do not raise open-port warnings for the whitelisted open ports.
	 * A whitelist is something that should be optionally provided per asset (or group of assets).
	 * E.g. When we scan a web server, the report shouldn't be concerned when TCP ports 80/443
	 * are open. In such a case TCP port 80 and TCP port 443 should be whitelisted.
	 */

	WhitelistedTCPPorts []uint16 `json:"whitelisted_tcp_ports"`
	WhitelistedUDPPorts []uint16 `json:"whitelisted_udp_ports"`
}

var (
	checkName = "vulcan-exposed-services"
	logger    = check.NewCheckLog(checkName)

	defaultTiming = 3

	whitelistedTCPPorts = []uint16{}
	whitelistedUDPPorts = []uint16{}

	exposedVuln = report.Vulnerability{
		Summary:       "Exposed Services",
		Description:   "At least one non-whitelisted port of the host is accessible from the public Internet.",
		Score:         report.SeverityThresholdMedium,
		ImpactDetails: "An attacker may be able to remotely connect to the network device through the exposed port.",
		Recommendations: []string{
			"Restrict access to the exposed services/ports from the Internet",
		},
		References: []string{
			"https://tools.ietf.org/html/rfc4778",
		},
	}
)

func uint16ArrayToString(a []uint16, delim string) string {
	return strings.Trim(strings.Replace(fmt.Sprint(a), " ", delim, -1), "[]")
}

func exposedPorts(target string, nmapReport *gonmap.NmapRun) []report.Vulnerability {
	gr := report.ResourcesGroup{
		Name: "Network Resources",
		Header: []string{
			"Hostname",
			"Port",
			"Protocol",
			"NmapState",
			"Service",
			"Version",
		},
	}

	add := false
	for _, host := range nmapReport.Hosts {
		for _, port := range host.Ports {
			/* If a UDP port is opened but not running a well-known service that can be
			 * discovered when nmap is sending some protocol-specific payload, the port
			 * will most likely be marked as open|filtered. Therefore, when scanning
			 * UDP ports we should not ignore the open|filtered state.
			 *
			 * I have rarely seen the open|filtered state in TCP port scans.
			 *
			 * More info about nmap states: https://nmap.org/book/man-port-scanning-basics.html
			 */
			if port.State.State != "open" && port.State.State != "open|filtered" {
				continue
			}

			add = true

			networkResource := map[string]string{
				"Hostname":  target,
				"Port":      strconv.Itoa(port.PortId),
				"Protocol":  port.Protocol,
				"NmapState": port.State.State,
				"Service":   port.Service.Product,
				"Version":   port.Service.Version,
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
	run := func(ctx context.Context, target, assetType, optJSON string, state checkstate.State) (err error) {
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

		/* Scan the default TCP ports and the default nmap UDP ports (which are 1000 of them),
		 * as reliable UDP port scanning takes a very very long time (a whole range UDP port scan
		 * can take more than 18 hours: https://nmap.org/book/man-port-scanning-techniques.html).
		 *
		 * We use the following two nmap commands:
		 *
		 *   For TCP scanning:
		 *     nmap -Pn -sT --exclude-ports <whitelisted-tcp-ports> <target>
		 *
		 *   For UDP scanning:
		 *     nmap -Pn -sV -sU --exclude-ports <whitelisted-udp-ports> <target>
		 *
		 *     -sT: Activates TCP connect scan.
		 *          SYN scan is the default and most popular scan option, but TCP connect is
		 *          faster. Since we don't care being stealthy when we scan our own infrastructure,
		 *          we choose the *faster* option.
		 * -sV -sU: Activates UDP scan with version detection.
		 *          UDP scan is activated with the -sU option. It can be combined with a TCP
		 *          scan type such as SYN scan (-sS) to check both protocols during the same run.
		 *          Version detection (-sV) can be used to help differentiate the truly open
		 *          ports from the filtered ones.
		 *     -Pn: Force scan the target even if it doesn't seem to be up.
		 *          Sometimes due to strong/good firewall rules, nmap may fail to determine that
		 *          the target is active and will skip further scanning without the -Pn option.
		 */

		// First proceed with the TCP scan
		nmapTCPParams := map[string]string{
			"-Pn": "",
			"-sT": "",
		}

		if len(opt.WhitelistedTCPPorts) != 0 {
			nmapTCPParams["--exclude-ports"] = uint16ArrayToString(opt.WhitelistedTCPPorts, ",")
		}

		nmapTCPRunner := nmap.NewNmapCheck(target, state, opt.Timing, opt.ReportProgress, nmapTCPParams)
		nmapTCPReport, _, err := nmapTCPRunner.Run(ctx)
		if err != nil {
			return err
		}

		vulnsTCP := exposedPorts(target, nmapTCPReport)
		state.AddVulnerabilities(vulnsTCP...)
		// End TCP scan

		// Then follow up with the UDP scan
		nmapUDPParams := map[string]string{
			"-Pn":               "",
			"-sU":               "",
			"-sV":               "",
			"--min-parallelism": "10",
			"--max-parallelism": "100",
		}

		if len(opt.WhitelistedUDPPorts) != 0 {
			nmapUDPParams["--exclude-ports"] = uint16ArrayToString(opt.WhitelistedUDPPorts, ",")
		}

		nmapUDPRunner := nmap.NewNmapCheck(target, state, opt.Timing, opt.ReportProgress, nmapUDPParams)
		nmapUDPReport, _, err := nmapUDPRunner.Run(ctx)
		if err != nil {
			return err
		}

		vulnsUDP := exposedPorts(target, nmapUDPReport)
		state.AddVulnerabilities(vulnsUDP...)
		// End UDP scan

		return nil
	}

	c := check.NewCheckFromHandler(checkName, run)
	c.RunAndServe()
}
