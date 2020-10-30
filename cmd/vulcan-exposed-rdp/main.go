package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	check "github.com/adevinta/vulcan-check-sdk"
	"github.com/adevinta/vulcan-check-sdk/helpers"
	checkstate "github.com/adevinta/vulcan-check-sdk/state"
	report "github.com/adevinta/vulcan-report"
)

type options struct {
	// TCP connection timeout.
	Timeout int `json:"timeout"`
	// TCP port to scan.
	Port string `json:"port"`
}

var (
	checkName      = "vulcan-exposed-rdp"
	defaultPort    = "3389"
	defaultTimeout = 2

	exposedRDP = report.Vulnerability{
		Summary:         "Exposed RDP Port",
		Description:     "The service is commonly used by Microsoft Remote Desktop, and exposing it may allow external attackers to gain access to the host.",
		Score:           report.SeverityThresholdMedium,
		Recommendations: []string{"Block access to the RDP port from the Internet."},
	}

	logger *logrus.Entry

	CRPDU      []byte
	CCPDURegex *regexp.Regexp

	CRPDUDef = []interface{}{
		// tpktHeader:
		// https://go.microsoft.com/fwlink/?LinkId=90541
		int8(3),    // Version.
		int8(0),    // Reserved.
		uint16(11), // Length.
		// X.224 Connection Request PDU:
		// https://go.microsoft.com/fwlink/?LinkId=90588
		int8(6),      // LI.
		byte('\xe0'), // CR CDT.
		uint16(0),    // DST REF.
		uint16(0),    // SRC REF.
		int8(0),      // Class option.
	}

	CCPDUDef = []string{
		// tpktHeader regex:
		// https://go.microsoft.com/fwlink/?LinkId=90541
		"\x03", // Version.
		"\x00", // Reserved.
		".{2}", // Length (2 bytes).
		// X.224 Connection Confirm PDU regex:
		// https://go.microsoft.com/fwlink/?LinkId=90588
		".{1}", // LI.
		".{1}", // CC CDT,
		".{5}", // Rest of the header.
		".*$",  // User data.
	}
)

// buildPDUs initializes the RDP PDUs based on the RDP protocol specification.
// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpbcgr/18a27ef9-6f9a-4501-b000-94b1fe3c2c10
func buildPDUs() error {
	buf := new(bytes.Buffer)

	for _, v := range CRPDUDef {
		err := binary.Write(buf, binary.BigEndian, v)
		if err != nil {
			return err
		}
	}

	CRPDU = buf.Bytes()

	var err error
	CCPDURegex, err = regexp.Compile(strings.Join(CCPDUDef, ""))

	return err
}

func isExposedRDP(host, port string, timeout int) []report.Vulnerability {
	srvAddr := fmt.Sprintf("%s:%s", host, port)

	conn, err := net.DialTimeout("tcp", srvAddr, time.Duration(timeout)*time.Second)
	if err != nil {
		logger.WithError(err).Debug("can not connect to the RDP endpoint")
		return nil
	}

	if _, err := conn.Write(CRPDU); err != nil {
		logger.WithError(err).Debug("can not write to the RDP connection")
		return nil
	}

	// Read just the Connection Confirm PDU header.
	b := make([]byte, 100)

	if _, err := conn.Read(b); err != nil {
		logger.WithError(err).Debug("can not read from the RDP connection")
		return nil
	}

	if CCPDURegex.Match(b) && b[5] == byte('\xd0') {
		exposedRDP.Details += fmt.Sprintf("RDP host detected in port: %s", port)
		return []report.Vulnerability{exposedRDP}
	}

	return nil
}

func run(ctx context.Context, target, assetType, optJSON string, state checkstate.State) (err error) {
	l := check.NewCheckLog(checkName)
	logger = l.WithFields(logrus.Fields{"target": target, "assetType": assetType, "options": optJSON})

	if err := buildPDUs(); err != nil {
		return err
	}

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

	if opt.Timeout == 0 {
		opt.Timeout = defaultTimeout
	}

	if opt.Port == "" {
		opt.Port = defaultPort
	}

	vulns := isExposedRDP(target, opt.Port, opt.Timeout)
	state.AddVulnerabilities(vulns...)

	return nil
}

func main() {
	c := check.NewCheckFromHandler(checkName, run)
	c.RunAndServe()
}
