/*
Copyright 2021 Adevinta
*/

package main

import (
	"context"
	"encoding/json"
	"regexp"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"

	check "github.com/adevinta/vulcan-check-sdk"
	"github.com/adevinta/vulcan-check-sdk/helpers"
	"github.com/adevinta/vulcan-check-sdk/helpers/nmap"
	checkstate "github.com/adevinta/vulcan-check-sdk/state"
	report "github.com/adevinta/vulcan-report"
	gonmap "github.com/lair-framework/go-nmap"
)

const defaultTiming = 4

type options struct {
	// Nmap timing parameter.
	Timing int `json:"timing"`
	// Return status updates on the progress of the check
	ReportProgress bool `json:"report_progress"`
	// List of potential ports to scan for.
	Ports []string `json:"ports"`
	// Regex to verify that the exposed service is a SMB/CIFS port.
	Regex string `json:"regex"`
}

var (
	checkName    = "vulcan-exposed-smb"
	defaultPorts = []string{
		"135",
		"139",
		"445",
	}
	defaultRegex = ""

	exposedSMB = report.Vulnerability{
		Summary:         "Exposed SMB/CIFS Ports",
		Description:     "These ports are commonly used by Microsoft Server Message Block Protocol / Common Internet File System, and exposing them to the internet is discouranged.",
		Score:           report.SeverityThresholdNone,
		Recommendations: []string{"Block access to SMB/CIFS related ports from the internet."},
	}

	logger *logrus.Entry
)

func isExposedSMB(target string, nmapReport *gonmap.NmapRun, r *regexp.Regexp) []report.Vulnerability {
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
				logger.WithFields(logrus.Fields{"port": port.PortId}).Debug("Port not open")
				continue
			}

			if r.String() != "" && !r.MatchString(port.Service.Product) {
				logger.WithFields(logrus.Fields{"port": port.PortId, "product": port.Service.Product}).Info("Product does not match regex")
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

			logger.WithFields(logrus.Fields{"resource": networkResource}).Info("Resource added")

		}
	}

	if add {
		exposedSMB.Resources = append(exposedSMB.Resources, gr)
		logger.WithFields(logrus.Fields{"vulnerability": exposedSMB}).Info("Vulnerability added")
		return []report.Vulnerability{exposedSMB}
	}

	return nil
}

func run(ctx context.Context, target, assetType, optJSON string, state checkstate.State) (err error) {
	l := check.NewCheckLog(checkName)
	logger = l.WithFields(logrus.Fields{"target": target, "assetType": assetType, "options": optJSON})

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

	if opt.Regex == "" {
		opt.Regex = defaultRegex
	}

	r, err := regexp.Compile(opt.Regex)
	if err != nil {
		return err
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

	vulns := isExposedSMB(target, nmapReport, r)
	state.AddVulnerabilities(vulns...)

	return nil
}

func main() {
	c := check.NewCheckFromHandler(checkName, run)
	c.RunAndServe()
}
