/*
Copyright 2019 Adevinta
*/

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"strconv"
	"strings"

	check "github.com/adevinta/vulcan-check-sdk"
	"github.com/adevinta/vulcan-check-sdk/helpers"
	checkstate "github.com/adevinta/vulcan-check-sdk/state"
	report "github.com/adevinta/vulcan-report"
	types "github.com/adevinta/vulcan-types"
	"github.com/sirupsen/logrus"
)

var (
	checkName        = "vulcan-masscan"
	masscanBin       = "masscan"
	defaultPortRange = "0-65535"

	exposedVuln = report.Vulnerability{
		Summary:       "Exposed Services",
		Description:   "At least one non-whitelisted port of the host is accessible from the public Internet.",
		Score:         report.SeverityThresholdNone,
		ImpactDetails: "An attacker may be able to remotely connect to the network device through the exposed port.",
		Recommendations: []string{
			"Restrict access to the exposed services/ports from the Internet",
		},
		References: []string{
			"https://tools.ietf.org/html/rfc4778",
		},
	}
)

type options struct {
	WhiteListedTCPPorts []uint16    `json:"whitelisted_tcp_ports"`
	PortRange           []portRange `json:"port_range"`
}

type portRange struct {
	Start uint16 `json:"start"`
	Stop  uint16 `json:"stop"`
}

func parsePortRange(pr []portRange) (string, error) {
	var res []string
	for _, p := range pr {
		var s string
		switch {
		case p.Start > p.Stop:
			return "", fmt.Errorf("invalid range: %v-%v", p.Start, p.Stop)
		case p.Start == p.Stop:
			s = fmt.Sprintf("%v", p.Start)
		case p.Start < p.Stop:
			s = fmt.Sprintf("%v-%v", p.Start, p.Stop)
		}
		res = append(res, s)
	}
	return strings.Join(res, ","), nil
}

func portExcluded(port uint16, exclude []uint16) bool {
	for _, p := range exclude {
		if p == port {
			return true
		}
	}
	return false
}

func exposedPorts(target string, res []Result, exclude []uint16) []report.Vulnerability {
	gr := report.ResourcesGroup{
		Name: "Network Resources",
		Header: []string{
			"Hostname",
			"Port",
			"Protocol",
			"State",
		},
	}

	add := false
	useIP := target == ""
	for _, r := range res {
		if useIP {
			target = r.IP
		}
		for _, port := range r.Ports {
			if port.Status != "open" || portExcluded(port.Port, exclude) {
				continue
			}

			add = true

			networkResource := map[string]string{
				"Hostname": target,
				"Port":     strconv.Itoa(int(port.Port)),
				"Protocol": port.Proto,
				"State":    port.Status,
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
		logger := check.NewCheckLog(checkName)
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

		dest := target
		solved := false
		switch {
		case types.IsIP(target), types.IsCIDR(target):
			break
		case types.IsHostname(target):
			// masscan doesn't accept hostnames as target.
			ips, err := net.LookupHost(target)
			if err != nil || len(ips) < 1 {
				e.WithError(err).Error("target can not be resolved")
				return err
			}
			dest = ips[0]
			solved = true
		default:
			e.Error("target is not a valid asset type")
			return fmt.Errorf("target %v is not a valid asset type", target)
		}

		portRange, err := parsePortRange(opt.PortRange)
		if err != nil {
			e.WithError(err).Error("port range incorrectly defined")
			return err
		}
		if portRange == "" {
			portRange = defaultPortRange
		}

		var scanner dumbScanner
		checker := check.NewProcessChecker(
			masscanBin,
			[]string{
				dest,
				fmt.Sprintf("-p%s", portRange),
				"-oJ",
				"/results.json",
			},
			bufio.ScanLines,
			&scanner,
		)

		if _, err := checker.Run(ctx); err != nil {
			return err
		}

		content, err := ioutil.ReadFile("/results.json")
		if err != nil {
			e.WithError(err).Error("results file not found")
			return err
		}
		if len(content) == 0 {
			return nil
		}

		var res []Result
		if err := json.Unmarshal(content, &res); err != nil {
			e.WithError(err).WithFields(logrus.Fields{"raw": string(content)}).Error("can not unmarshal")
			return err
		}
		e.WithFields(logrus.Fields{"parsed": res}).Debug("Results parsed")

		var vulnsTCP []report.Vulnerability
		if solved {
			vulnsTCP = exposedPorts(target, res, opt.WhiteListedTCPPorts)
		} else {
			vulnsTCP = exposedPorts("", res, opt.WhiteListedTCPPorts)
		}
		state.AddVulnerabilities(vulnsTCP...)

		return nil
	}

	c := check.NewCheckFromHandler(checkName, run)
	c.RunAndServe()
}

/*

Output example:

	[
	{   "ip": "80.91.34.85",   "timestamp": "1540373529", "ports": [ {"port": 443, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 37} ] }
	,
	{   "ip": "80.91.34.85",   "timestamp": "1540373529", "ports": [ {"port": 80, "proto": "tcp", "status": "open", "reason": "syn-ack", "ttl": 37} ] }
	]

*/

type Result struct {
	IP        string `json:"ip"`
	Timestamp string `json:"timestamp"`
	Ports     []Port `json:"ports"`
}

type Port struct {
	Port   uint16 `json:"port"`
	Proto  string `json:"proto"`
	Status string `json:"status"`
	Reason string `json:"reason"`
	TTL    int    `json:"ttl"`
}

type dumbScanner struct{}

func (s dumbScanner) ProcessOutputChunk(chunk []byte) bool {
	return true
}
