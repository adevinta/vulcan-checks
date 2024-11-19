/*
Copyright 2019 Adevinta
*/

/*
The checks are done based in combinations of MAIL FROM and RCPT TO commands. The list is hardcoded in the source file.
The script will output all the working combinations that the server allows if nmap is in verbose mode otherwise
the script will print the number of successful tests. The script will not output if the server requires authentication.
*/

package main

import (
	"context"
	"encoding/json"
	"fmt"
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

const (
	checkName = "vulcan-smtp-open-relay"

	defaultTiming          = 3
	openRelayTrueSubString = "Server is an open relay"
	scriptName             = "smtp-open-relay"
)

var (
	defaultPorts = []string{"25", "465", "587"}

	// https://www.rapid7.com/db/vulnerabilities/smtp-general-openrelay
	openRelay = report.Vulnerability{
		CWEID:   269,
		Summary: "SMTP Open Relay",
		Description: "An SMTP server that works as an open relay, is a email server that does not verify if " +
			"the user is authorised to send email from the specified email address. Therefore, users would be " +
			"able to send email originating from any third-party email address that they want.",
		Score:         report.SeverityThresholdHigh,
		ImpactDetails: "It is possible to initiate the attack remotely. No form of authentication is needed for exploitation.",
		Recommendations: []string{
			"You need to secure your mail system against third-party relay. Check references for details on fixing this problem.",
		},
		References: []string{
			"https://en.wikipedia.org/wiki/Open_mail_relay",
		},
	}
)

func evalReport(target string, nmapReport *gonmap.NmapRun, state checkstate.State) {
	for _, host := range nmapReport.Hosts {
		for _, port := range host.Ports {
			if port.State.State != "open" {
				continue
			}
			for _, script := range port.Scripts {
				if script.Id != scriptName {
					continue
				} else if !strings.Contains(script.Output, openRelayTrueSubString) {
					continue
				}
				vuln := openRelay
				vuln.AffectedResource = fmt.Sprintf("%d/%s", port.PortId, port.Protocol)
				vuln.Fingerprint = helpers.ComputeFingerprint()
				vuln.Labels = []string{"issue", "smtp", "discovery"}
				state.AddVulnerabilities(vuln)
			}
		}
	}
}

func main() {
	run := func(ctx context.Context, target, assetType, optJSON string, state checkstate.State) (err error) {
		logger := check.NewCheckLog(checkName)
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
			"-Pn":      "",
			"-p":       strings.Join(opt.Ports, ","),
			"--open":   "",
			"--script": "smtp-open-relay.nse",
		}

		nmapRunner := nmap.NewNmapCheck(target, state, opt.Timing, opt.ReportProgress, nmapParams)
		nmapReport, _, err := nmapRunner.Run(ctx)
		if err != nil {
			return err
		}

		evalReport(target, nmapReport, state)

		return nil
	}

	c := check.NewCheckFromHandler(checkName, run)
	c.RunAndServe()
}
