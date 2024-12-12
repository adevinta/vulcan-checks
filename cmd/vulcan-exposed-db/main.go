/*
Copyright 2019 Adevinta
*/

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	gonmap "github.com/lair-framework/go-nmap"
	"github.com/sirupsen/logrus"

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
	// Regex to verify that the exposed service is a database.
	Regex string `json:"regex"`
}

var (
	checkName = "vulcan-exposed-db"

	defaultTiming = 3
	defaultPorts  = []string{
		"5432",                    // PostgreSQL
		"1521",                    // Oracle
		"1433",                    // SQL Server
		"3306",                    // MySQL
		"27017", "27018", "27019", // MongoDB
		"6379", "16379", "26379", // Redis
		"7000", "7001", "9042", // Cassandra
		"9200", "9300", // Elasticsearch
	}
	defaultRegex = `(?i)(SQL|Database|Mongo|Redis|Elasticsearch|Cassandra|Oracle)`

	exposedVuln = report.Vulnerability{
		CWEID:         284,
		Summary:       "Exposed Database Ports",
		Description:   "A port likely belonging to a database is accessible from the public internet.",
		Score:         report.SeverityThresholdMedium,
		ImpactDetails: "An attacker may be able to remotely connect to the database service through the exposed port. If no authentication is implemented, it might be possible to access stored data and, even if authentication is implemented, it may be possible to perform brute force login attempts to access such data. An attacker can also attempt to remotely exploit any vulnerabilities present on the database service to obtain access to the server itself.",
		Recommendations: []string{
			"Restrict access to the database service port at the network level.",
		},
	}
)

func exposedDatabases(target string, nmapReport *gonmap.NmapRun, databaseRegex *regexp.Regexp, e *logrus.Entry) []report.Vulnerability {
	vulns := []report.Vulnerability{}
	for _, host := range nmapReport.Hosts {
		for _, port := range host.Ports {
			if port.State.State != "open" {
				e.WithFields(logrus.Fields{"port": port.PortId}).Debug("Port not open")
				continue
			}

			if !databaseRegex.MatchString(port.Service.Product) {
				e.WithFields(logrus.Fields{"port": port.PortId, "product": port.Service.Product}).Debug("Product does not match regex")
				continue
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
			networkResource := map[string]string{
				"Hostname": target,
				"Port":     strconv.Itoa(port.PortId),
				"Protocol": port.Protocol,
				"Service":  port.Service.Product,
				"Version":  port.Service.Version,
			}
			gr.Rows = append(gr.Rows, networkResource)
			v := exposedVuln
			v.Resources = []report.ResourcesGroup{gr}
			v.AffectedResource = fmt.Sprintf("%d/%s", port.PortId, port.Protocol)
			v.Fingerprint = helpers.ComputeFingerprint(port.Service.Product, port.Service.Version)
			v.Labels = []string{"issue", "db"}
			vulns = append(vulns, v)
		}
	}
	return vulns
}

func main() {
	run := func(ctx context.Context, target, assetType, optJSON string, state checkstate.State) (err error) {
		logger := check.NewCheckLogFromContext(ctx, checkName)
		e := logger.WithFields(logrus.Fields{"target": target, "options": optJSON})

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

		databaseRegex, err := regexp.Compile(opt.Regex)
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

		vulns := exposedDatabases(target, nmapReport, databaseRegex, e)
		state.AddVulnerabilities(vulns...)

		return nil
	}

	c := check.NewCheckFromHandler(checkName, run)
	c.RunAndServe()
}
