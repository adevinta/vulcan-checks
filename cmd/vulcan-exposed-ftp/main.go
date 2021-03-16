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
	// List of ports that will be scanned
	Ports []string `json:"ports"`
	// Scanning allowed open FTP Ports
	AllowedOpenPorts bool `json:"allowed"`
	// Credentials for bounce attack
	Password string `json:"password"`
	Login    string `json:"username"`
	// Host to try connecting to with the PORT command
	Host string `json:"checkhost"`
}

var (
	checkName              = "vulcan-exposed-ftp"
	logger                 = check.NewCheckLog(checkName)
	anonScriptID           = "ftp-anon"
	bounceScriptID         = "ftp-bounce"
	anonLoginAllowedString = "Anonymous FTP login allowed"
	bounceAllowedString    = "bounce working!"
	scriptArgs             = "ftp-anon.maxlist=0"
	defaultTiming          = 3
	defaultPorts           = []string{
		"20", // File Transfer Protocol (FTP) data transfer
		"21", // File Transfer Protocol (FTP) control (command)
		//"22",	// SFTP // commenting out because it is covered by exposed SSH check
		"69",  // TFTP
		"989", // FTPS Protocol (data), FTP over TLS/SSL
		"990", // FTPS Protocol (control), FTP over TLS/SSL
	}

	exposedVuln = report.Vulnerability{
		Summary:         "Exposed FTP Ports",
		Description:     "An attacker may be able to use the exposed port to exploit a vulnerability in the service.",
		Score:           report.SeverityThresholdMedium,
		Recommendations: []string{"Block access to FTP ports from the internet."},
	}

	anonLogins = report.Vulnerability{
		Summary:         "FTP Allows Anonymous Login",
		Description:     "Service can be accessed by anonymous users.",
		Score:           report.SeverityThresholdHigh,
		Recommendations: []string{"Disable anonymous login."},
	}

	bounceAllowed = report.Vulnerability{
		Summary:     "FTP Allows Port Scanning Using FTP Bounce Method",
		Description: "Service can be used as a MitM for remote port scanning.",
		Score:       report.SeverityThresholdMedium,
		Recommendations: []string{
			"Allow an FTP server to only make data connections to the same host that the control connection originated from.",
			"Block FTP control connections that come from reserved ports.",
			"Only allowing passive-mode client data connections.",
		},
	}
)

func exposedFTP(target string, nmapReport *gonmap.NmapRun) []report.Vulnerability {
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
	var vulns []report.Vulnerability
	for _, host := range nmapReport.Hosts {
		for _, port := range host.Ports {
			if port.State.State != "open" || !strings.Contains(port.Service.Name, "ftp") {
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

			// Check scripts
			for _, script := range port.Scripts {
				if script.Id != anonScriptID && script.Id != bounceScriptID {
					continue
				} else if script.Id == anonScriptID && strings.Contains(script.Output, anonLoginAllowedString) {
					v := anonLogins
					v.Details = fmt.Sprintf("Port: %v", port.PortId)
					vulns = append(vulns, v)
				} else if script.Id == bounceScriptID && strings.Contains(script.Output, bounceAllowedString) {
					v := bounceAllowed
					v.Details = fmt.Sprintf("Port: %v", port.PortId)
					vulns = append(vulns, v)
				}
			}
		}
	}

	if add {
		exposedVuln.Resources = append(exposedVuln.Resources, gr)
		vulns = append(vulns, exposedVuln)
	}
	return vulns
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
		} else if opt.AllowedOpenPorts {
			exposedVuln.Score = report.SeverityThresholdNone
		}

		if opt.Password != "" {
			scriptArgs += ",ftp-bounce.password=" + opt.Password
		}
		if opt.Login != "" {
			scriptArgs += ",ftp-bounce.username=" + opt.Login
		}
		if opt.Host != "" {
			scriptArgs += ",ftp-bounce.checkhost=" + opt.Host
		}

		// Scan with version detection.
		nmapParams := map[string]string{
			"-Pn":      "",
			"-sV":      "",
			"-p":       strings.Join(opt.Ports, ","),
			"--script": "ftp-anon,ftp-bounce",
			// disable files listing entirely
			"--script-args": scriptArgs,
		}

		nmapRunner := nmap.NewNmapCheck(target, state, opt.Timing, nmapParams)
		nmapReport, _, err := nmapRunner.Run(ctx)
		if err != nil {
			return err
		}

		vulns := exposedFTP(target, nmapReport)
		state.AddVulnerabilities(vulns...)

		return nil
	}

	c := check.NewCheckFromHandler(checkName, run)
	c.RunAndServe()
}
