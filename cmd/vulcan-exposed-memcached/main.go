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
	"github.com/adevinta/vulcan-check-sdk/state"
	report "github.com/adevinta/vulcan-report"
)

var (
	checkName = "vulcan-exposed-memcached"
	command   = "version\r\n"
	resRegex  = "VERSION (.+)\r\n$"
	// According to the specs, a UDP request must contain an frame header:
	// https://github.com/memcached/memcached/blob/master/doc/protocol.txt
	udpHeader = "\x00\x00\x00\x00\x00\x01\x00\x00"
	e         *logrus.Entry
)

type options struct {
	// Override default port.
	Port int `json:"port"`
}

func main() {
	c := check.NewCheckFromHandler(checkName, run)
	c.RunAndServe()
}

func run(ctx context.Context, target, assetType, optJSON string, state state.State) error {
	logger := check.NewCheckLog(checkName)
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

	e.Debug("checking if there is a memcached in the tcp port")
	vulnerable, version, err := isMemcachedExposed("tcp", command, target, opt.Port)
	if err != nil {
		return err
	}
	if vulnerable {
		networkResource := map[string]string{
			"Hostname": target,
			"Port":     strconv.Itoa(opt.Port),
			"Protocol": "tcp",
			"Service":  "Memcached",
			"Version":  version,
		}
		gr.Rows = append(gr.Rows, networkResource)
	}

	e.Debug("checking if there is a memcached in the udp port")
	udp, version, err := isMemcachedExposed("udp", udpHeader+command, target, opt.Port)
	if err != nil {
		return err
	}
	if udp {
		networkResource := map[string]string{
			"Hostname": target,
			"Port":     strconv.Itoa(opt.Port),
			"Protocol": "udp",
			"Service":  "Memcached",
			"Version":  version,
		}
		gr.Rows = append(gr.Rows, networkResource)
	}

	if udp || vulnerable {
		exposedMemcachedVuln.Resources = append(exposedMemcachedVuln.Resources, gr)
		state.AddVulnerabilities(exposedMemcachedVuln)
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

	fmt.Fprintf(conn, data)

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
