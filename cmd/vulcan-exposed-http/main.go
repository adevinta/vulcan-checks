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
	checkName = "vulcan-exposed-http"
	logger    = check.NewCheckLog(checkName)

	defaultTiming = 3
	defaultPorts  = []string{
		"80",    // HTTP
		"280",   // http-mgmt
		"443",   // HTTPS
		"591",   // FileMaker 6.0 (and later) Web Sharing (HTTP Alternate, also see port 80)
		"593",   // HTTP RPC Ep Map, Remote procedure call over Hypertext Transfer Protocol, often used by Distributed Component Object Model services and Microsoft Exchange Server
		"832",   // NETCONF for SOAP over HTTPS
		"981",   // Remote HTTPS management for firewall devices running embedded Check Point VPN-1 software
		"1311",  // Dell OpenManage HTTPS
		"2480",  // OrientDB database listening for HTTP client connections
		"3000",  // default Grafana port
		"4444",  // I2P HTTP proxy
		"4445",  // I2P HTTPS proxy
		"4567",  // Sinatra default server port in development mode (HTTP)
		"5000",  // Flask Development Webserver
		"5104",  // IBM Tivoli Framework NetCOOL/Impact HTTP Service
		"5601",  // default Kibana port
		"5800",  // VNC remote desktop protocol over HTTP
		"5988",  // CIM XML transactions over HTTP—VMware vCenter ESXi management
		"5989",  // CIM XML transactions over HTTPS—VMware vCenter ESXi management
		"7001",  // Default for BEA WebLogic Server's HTTP server, though often changed during installation
		"7002",  // Default for BEA WebLogic Server's HTTPS server, though often changed during installation
		"8000",  // HTTP Proxy port
		"8008",  // Alternative port for HTTP. See also ports 80 and 8080; IBM HTTP Server administration default
		"8080",  // Alternative port for HTTP. See also ports 80 and 8008.
		"8081",  // Alternative port for HTTP
		"8088",  // Asterisk management access via HTTP
		"8222",  // VMware Server Management User Interface (insecure Web interface). See also port 8333
		"8243",  // HTTPS listener for Apache Synapse
		"8280",  // HTTP listener for Apache Synapse
		"8333",  // VMware Server Management User Interface (secure Web interface). See also port 8222
		"8443",  // Alternative port for HTTPS.
		"8530",  // Windows Server Update Services over HTTP
		"8531",  // Windows Server Update Services over HTTPS
		"8880",  // IBM WebSphere Application Server SOAP connector
		"8887",  // HyperVM over HTTP
		"8888",  // HyperVM over HTTPS
		"8983",  // Apache Solr
		"9000",  // SonarQube Web Server
		"9080",  // WebSphere Application Server HTTP Transport (port 1) default
		"9443",  // VMware Websense Triton console (HTTPS port used for accessing and administrating a vCenter Server via the Web Management Interface)
		"11371", // OpenPGP HTTP key server
		"12443", // IBM HMC web browser management access over HTTPS instead of default port 443
		"18091", // memcached Internal REST HTTPS for SSL
		"18092", // memcached Internal CAPI HTTPS for SSL
	}
)

func exposedHTTP(target string, nmapReport *gonmap.NmapRun, state checkstate.State) {
	for _, host := range nmapReport.Hosts {
		for _, port := range host.Ports {
			if port.State.State != "open" || !strings.Contains(port.Service.Name, "http") {
				continue
			}
			v := report.Vulnerability{
				AffectedResource: fmt.Sprintf("%d/%s", port.PortId, port.Protocol),
				Labels:           []string{port.Protocol, "issue"},
				Fingerprint:      helpers.ComputeFingerprint(port.Service.Product, port.Service.Version),
				Summary:          "Exposed HTTP Port",
				Description:      "An HTTP server is listening at least in one port ot the server.",
				Score:            report.SeverityThresholdNone,
				Resources: []report.ResourcesGroup{{
					Name: "Network Resources",
					Header: []string{
						"Hostname",
						"Port",
						"Protocol",
						"Service",
						"Version",
						"SSL",
					},
					Rows: []map[string]string{
						{
							"Hostname": target,
							"Port":     strconv.Itoa(port.PortId),
							"Protocol": port.Protocol,
							"Service":  port.Service.Product,
							"Version":  port.Service.Version,
							"SSL": func() string {
								if strings.EqualFold(port.Service.Tunnel, "ssl") {
									return "yes"
								}
								return ""
							}(),
						},
					},
				},
				}}

			state.AddVulnerabilities(v)
		}
	}
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

		if len(opt.Ports) == 0 {
			opt.Ports = defaultPorts
		}

		// Scan with version detection.
		nmapParams := map[string]string{
			"-Pn": "",
			"-sV": "",
			"-p":  strings.Join(opt.Ports, ","),
		}

		nmapRunner := nmap.NewNmapCheck(target, state, opt.Timing, opt.ReportProgress, nmapParams)
		nmapReport, _, err := nmapRunner.Run(ctx)
		if err != nil {
			return err
		}

		exposedHTTP(target, nmapReport, state)

		return nil
	}

	c := check.NewCheckFromHandler(checkName, run)
	c.RunAndServe()
}
