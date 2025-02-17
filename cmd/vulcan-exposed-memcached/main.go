/*
Copyright 2019 Adevinta
*/

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"

	check "github.com/adevinta/vulcan-check-sdk"
	"github.com/adevinta/vulcan-check-sdk/helpers"
	checkstate "github.com/adevinta/vulcan-check-sdk/state"
	report "github.com/adevinta/vulcan-report"
)

var (
	checkName = "vulcan-exposed-memcached"
	command   = "version\r\n"
	resRegex  = "VERSION (.+)\r\n$"
	// According to the specs, a UDP request must contain an frame header:
	// https://github.com/memcached/memcached/blob/master/doc/protocol.txt
	udpHeader = "\x00\x00\x00\x00\x00\x01\x00\x00"

	// targets defines the payload to be sent depending on the protocol being
	// tested.
	targets = map[string]string{
		"tcp": command,
		"udp": udpHeader + command,
	}

	exposedMemcachedVuln = report.Vulnerability{
		Summary: "Exposed Memcached Server",
		Description: "Memcached is a server meant to be run in trusted networks." +
			" Otherwise, a remote attacker can execute memcached commands (like adding" +
			" or removing items from the cache, etc.) against the server.\n\n" +
			"Apart from that, if the UDP port of the memcached is exposed" +
			" the server is vulnerable to be used it in UDP Amplification Attacks (DDoS).",
		Score: report.SeverityThresholdHigh,
		CWEID: 284,
		Recommendations: []string{
			"Do not expose the memcached server to the Internet.",
			"If running in an internal trusted network, implement authentication.",
			"Disable the UDP port of the memcached server.",
		},
		References: []string{
			"https://github.com/memcached/memcached/wiki/SASLHowto",
			"https://github.com/memcached/memcached/blob/master/doc/protocol.txt",
			"https://tools.cisco.com/security/center/viewAlert.x?alertId=57020&vs_f=Alert%20RSS&vs_cat=Security%20Intelligence&vs_type=RSS&vs_p=Memcached%20Network%20Message%20Volume%20Denial%20of%20Service%20Vulnerability&vs_k=1",
		},
		Labels: []string{"issue"},
	}

	e *logrus.Entry
)

type options struct {
	// Override default port.
	Port int `json:"port"`
}

func main() {
	c := check.NewCheckFromHandler(checkName, run)
	c.RunAndServe()
}

func run(ctx context.Context, target, assetType, optJSON string, state checkstate.State) error {
	logger := check.NewCheckLogFromContext(ctx, checkName)
	e = logger.WithFields(logrus.Fields{"target": target, "assetType": assetType, "options": optJSON})

	if target == "" {
		return errors.New("missing check target")
	}

	var opt options
	if optJSON != "" {
		if err := json.Unmarshal([]byte(optJSON), &opt); err != nil {
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

	for protocol, data := range targets {
		e.WithFields(logrus.Fields{"protocol": protocol}).Debug("checking if there is a memcached in the port")

		vulnerable, version, err := isMemcachedExposed(protocol, data, target, opt.Port)
		if err != nil {
			return err
		}
		if !vulnerable {
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
			"Port":     strconv.Itoa(opt.Port),
			"Protocol": protocol,
			"Service":  "Memcached",
			"Version":  version,
		}
		gr.Rows = append(gr.Rows, networkResource)

		vuln := exposedMemcachedVuln
		vuln.AffectedResource = fmt.Sprintf("%v/%v", opt.Port, protocol)
		vuln.Fingerprint = helpers.ComputeFingerprint(version)
		vuln.Resources = append(vuln.Resources, gr)

		state.AddVulnerabilities(vuln)

	}

	return nil
}

func isMemcachedExposed(proto, data, target string, port int) (exposed bool, version string, err error) {
	conn, err := net.DialTimeout(proto, fmt.Sprintf("%v:%v", target, port), 5*time.Second)
	if err != nil {
		if shouldReportError(err) {
			return false, "", err
		}

		return false, "", nil
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return false, "", err
	}

	fmt.Fprint(conn, data)

	res, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		if shouldReportError(err) {
			return false, "", err
		}

		return false, "", nil
	}

	e.WithFields(logrus.Fields{"response": res}).Debug("response received")

	r, err := regexp.Compile(resRegex)
	if err != nil {
		return false, "", err
	}

	if !r.MatchString(res) {
		return false, "", fmt.Errorf("unknown response: %v", res)
	}

	version = r.FindStringSubmatch(res)[1]
	e.WithFields(logrus.Fields{"proto": proto, "version": version}).Debug("version found")

	return true, version, nil
}

func shouldReportError(err error) bool {
	e.WithError(err).WithFields(logrus.Fields{"error_type": reflect.TypeOf(err)}).Debug("Error connecting or reading")

	switch t := err.(type) {
	case *net.OpError:
		if t.Op == "read" {
			return false
		}

		if t.Op == "dial" && (strings.Contains(err.Error(), "connection refused") || t.Timeout()) {
			return false
		}
	case syscall.Errno:
		if t == syscall.ECONNREFUSED {
			return false
		}
	case net.Error:
		if t.Timeout() {
			return false
		}
	}

	return true
}
