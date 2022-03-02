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

	check "github.com/adevinta/vulcan-check-sdk"
	"github.com/adevinta/vulcan-check-sdk/helpers"
	"github.com/adevinta/vulcan-check-sdk/helpers/nmap"
	checkstate "github.com/adevinta/vulcan-check-sdk/state"
	report "github.com/adevinta/vulcan-report"
	gonmap "github.com/lair-framework/go-nmap"
)

type options struct {
	// Nmap timing parameter.
	Timing int `json:"timing"`
	// Return status updates on the progress of the check
	ReportProgress bool `json:"report_progress"`
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

	exposedFTP = report.Vulnerability{
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

func processExposedFTPVulns(target string, nmapReport *gonmap.NmapRun, state checkstate.State) {
	var vulns []report.Vulnerability
	for _, host := range nmapReport.Hosts {
		for _, port := range host.Ports {
			if port.State.State != "open" || !strings.Contains(port.Service.Name, "ftp") {
				continue
			}

			v := exposedFTP
			v.AffectedResource = fmt.Sprintf("%d/%s", port.PortId, port.Protocol)
			v.Labels = []string{"ftp", "issue"}

			networkResource := map[string]string{
				"Hostname": target,
				"Port":     strconv.Itoa(port.PortId),
				"Protocol": port.Protocol,
				"Service":  port.Service.Product,
				"Version":  port.Service.Version,
			}
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
			gr.Rows = append(gr.Rows, networkResource)
			v.Resources = []report.ResourcesGroup{gr}
			v.Fingerprint = helpers.ComputeFingerprint(port.Service.Product, port.Service.Version, "exposed")
			vulns = append(vulns, v)

			// Check scripts
			for _, script := range port.Scripts {
				if script.Id == anonScriptID && strings.Contains(script.Output, anonLoginAllowedString) {
					v := anonLogins
					v.Resources = []report.ResourcesGroup{gr}
					v.AffectedResource = fmt.Sprintf("%d/%s", port.PortId, port.Protocol)
					v.Labels = []string{"ftp", "issue"}
					v.Fingerprint = helpers.ComputeFingerprint(port.Service.Product, port.Service.Version, "anon")
					vulns = append(vulns, v)
				} else if script.Id == bounceScriptID && strings.Contains(script.Output, bounceAllowedString) {
					v := bounceAllowed
					v.Resources = []report.ResourcesGroup{gr}
					v.AffectedResource = fmt.Sprintf("%d/%s", port.PortId, port.Protocol)
					v.Labels = []string{"ftp", "issue"}
					v.Fingerprint = helpers.ComputeFingerprint(port.Service.Product, port.Service.Version, "bounce")
					vulns = append(vulns, v)
				}
			}
		}
	}
	state.AddVulnerabilities(vulns...)
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
			exposedFTP.Score = report.SeverityThresholdNone
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

		nmapRunner := nmap.NewNmapCheck(target, state, opt.Timing, opt.ReportProgress, nmapParams)
		nmapReport, _, err := nmapRunner.Run(ctx)
		if err != nil {
			return err
		}

		processExposedFTPVulns(target, nmapReport, state)

		return nil
	}

	c := check.NewCheckFromHandler(checkName, run)
	c.RunAndServe()
}
