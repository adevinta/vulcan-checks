/*
Copyright 2021 Adevinta
*/

package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httputil"
	"regexp"
	"strconv"
	"strings"
	"time"

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
	// List of potential ports to scan for.
	Ports []string `json:"ports"`
	// Regex to verify that the exposed service is a hadoop port.
	Regex string `json:"regex"`
}

var (
	checkName = "vulcan-exposed-hdfs"
	// TODO: consider making a more extensive research on Hadoop to include all the critical ports that shouldn't be exposed:
	// https://docs.hortonworks.com/HDPDocuments/HDP3/HDP-3.0.0/administration/content/reference.html
	// https://ambari.apache.org/1.2.3/installing-hadoop-using-ambari/content/reference_chap2.html
	defaultPorts = []string{
		"8088", // ResourceManager HTTP. When open we can kill YARN applications, run new applications, obtain information about the current status of a YARN cluster.
		"8090",
		"14000", // HttpFs. When open we can do whatever we want with HDFS files (read, write, list, delete).
		"11000", // Oozie Server. When open we can inject an oozie job (e.g. run a bash script).
		"8020",  // HDFS NameNode. When open we can delete, update permissions, change ownership of HDFS files.
		"8032",
		"10000", // HiveServer. When open we can connect to the HiveServer2 and run queries.
		"50070", // HDFS console.
	}
	defaultRegex = ""

	exposedHDFS = report.Vulnerability{
		Summary:         "Exposed HDFS Ports",
		Description:     "The ports are commonly used by Hadoop Distributed File System, and exposing them may allow to execute jobs by external attackers.",
		Score:           report.SeverityThresholdNone,
		Recommendations: []string{"Block access to Hadoop related ports from the internet."},
	}

	logger *logrus.Entry
)

func isExposedHDFS(target string, nmapReport *gonmap.NmapRun, r *regexp.Regexp) []report.Vulnerability {
	gr := report.ResourcesGroup{
		Name: "Network Resources",
		Header: []string{
			"Hostname",
			"Port",
			"Protocol",
			"Service",
			"Version",
			"Confirmed",
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

			c := false
			if confirmed(target, strconv.Itoa(port.PortId), port.Service.Product) {
				exposedHDFS.Score = report.SeverityThresholdCritical
				c = true
			}

			networkResource := map[string]string{
				"Hostname":  target,
				"Port":      strconv.Itoa(port.PortId),
				"Protocol":  port.Protocol,
				"Service":   port.Service.Product,
				"Version":   port.Service.Version,
				"Confirmed": strconv.FormatBool(c),
			}
			gr.Rows = append(gr.Rows, networkResource)

			logger.WithFields(logrus.Fields{"resource": networkResource}).Info("Resource added")

		}
	}

	if add {
		exposedHDFS.Resources = append(exposedHDFS.Resources, gr)
		logger.WithFields(logrus.Fields{"vulnerability": exposedHDFS}).Info("Vulnerability added")
		return []report.Vulnerability{exposedHDFS}
	}

	return nil
}

func confirmed(host, port, product string) bool {
	switch port {
	case "8088":
		fallthrough
	case "8090":
		return checkHTTP(host, port, "yarn")
	case "14000":
		return checkHTTP(host, port, "(?i)httpfs")
	case "11000":
		return checkHTTP(host, port, "(?i)oozie")
	case "50070":
		return checkHTTP(host, port, "(?i)hadoop")
	case "10000":
		fallthrough
	case "8020":
		fallthrough
	case "8032":
		m, _ := regexp.Match("(?i)hadoop", []byte(product))
		return m
	}

	return false
}

func checkHTTP(host, port, regex string) bool {
	// Set Timeout for HTTP request.
	timeout := 1 * time.Second
	// Do not verify SSL certificate.
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   timeout,
	}

	switch {
	case checkHTTPWithScheme(client, "http", host, port, regex):
		logger.WithFields(logrus.Fields{"host": host, "port": port}).Info("match found")
		return true
	case checkHTTPWithScheme(client, "https", host, port, regex):
		logger.WithFields(logrus.Fields{"host": host, "port": port}).Info("match found")
		return true
	}
	return false
}

func checkHTTPWithScheme(client *http.Client, scheme, host, port, regex string) bool {
	resp, err := client.Get(fmt.Sprintf("%s://%s:%s", scheme, host, port))
	if err != nil {
		return false
	}

	contents, err := httputil.DumpResponse(resp, true)
	if err != nil {
		logger.WithError(err).Error("can not retrieve response contents")
	}
	logger.WithFields(logrus.Fields{"content": []byte(contents)}).Debug("HTTP response received")

	m, err := regexp.Match(regex, contents)
	if err != nil {
		logger.WithFields(logrus.Fields{"regex": regex}).WithError(err).Error("error matching the regex")
	}
	return m
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

	nmapRunner := nmap.NewNmapCheck(target, state, opt.Timing, nmapParams)
	nmapReport, _, err := nmapRunner.Run(ctx)
	if err != nil {
		return err
	}

	vulns := isExposedHDFS(target, nmapReport, r)
	state.AddVulnerabilities(vulns...)

	return nil
}

func main() {
	c := check.NewCheckFromHandler(checkName, run)
	c.RunAndServe()
}
