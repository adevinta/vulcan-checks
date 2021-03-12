/*
Copyright 2021 Adevinta
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
	// List of potential database ports to scan for.
	Ports []string `json:"ports"`
}

var (
	checkName = "vulcan-smtp-open-relay"
	logger    = check.NewCheckLog(checkName)

	defaultTiming          = 3
	defaultPorts           = []string{"25", "465", "587"}
	openRelayTrueSubString = "Server is an open relay"
	scriptName             = "smtp-open-relay"

	// NOTE: should we increase the score to critical?
	// https://www.rapid7.com/db/vulnerabilities/smtp-general-openrelay
	openRelay = report.Vulnerability{
		CWEID:   269,
		Summary: "SMTP Open Relay",
		Description: "An SMTP server that works as an open relay, is a email server that does not verify if " +
			"the user is authorised to send email from the specified email address. Therefore, users would be " +
			"able to send email originating from any third-party email address that they want.",
		Score:         report.SeverityThresholdMedium,
		ImpactDetails: "It is possible to initiate the attack remotely. No form of authentication is needed for exploitation.",
		Recommendations: []string{
			"You need to secure your mail system against third-party relay. Check references for details on fixing this problem.",
		},
		References: []string{
			"https://en.wikipedia.org/wiki/Open_mail_relay",
		},
	}
)

func evalReport(target string, nmapReport *gonmap.NmapRun) []report.Vulnerability {
	gr := report.ResourcesGroup{
		Name: "Network Resources",
		Header: []string{
			"Hostname",
			"Port",
		},
	}

	add := false
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

				add = true

				networkResource := map[string]string{
					"Hostname": target,
					"Port":     strconv.Itoa(port.PortId),
				}
				gr.Rows = append(gr.Rows, networkResource)
			}
		}
	}

	if add {
		openRelay.Resources = append(openRelay.Resources, gr)
		return []report.Vulnerability{openRelay}
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

		nmapRunner := nmap.NewNmapCheck(target, state, opt.Timing, nmapParams)
		nmapReport, _, err := nmapRunner.Run(ctx)
		if err != nil {
			return err
		}

		vulns := evalReport(target, nmapReport)
		state.AddVulnerabilities(vulns...)

		return nil
	}

	c := check.NewCheckFromHandler(checkName, run)
	c.RunAndServe()
}
