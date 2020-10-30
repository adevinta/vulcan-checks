package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	check "github.com/adevinta/vulcan-check-sdk"
	"github.com/adevinta/vulcan-check-sdk/helpers"
	checkstate "github.com/adevinta/vulcan-check-sdk/state"
	report "github.com/adevinta/vulcan-report"
)

var (
	checkName      = "vulcan-exposed-bgp"
	logger         = check.NewCheckLog(checkName)
	defaultTimeout = 30 * time.Second
	defaultBGPPort = 179

	// NOTE: should we DROP the severity level to LOW?
	// https://www.acunetix.com/vulnerabilities/network/vulnerability/bgp-detection/
	exposedBGP = report.Vulnerability{
		Summary: fmt.Sprintf("Exposed BGP speaker on port %v", defaultBGPPort),
		Description: "This check tests for exposed BGP port on the router. According to best practices, BGP port should not be open to the public internet and access to it" +
			"should be restricted only to participating BGP neighbours.",
		Score:         report.SeverityThresholdNone,
		ImpactDetails: "BGP is exposed and attacks can be carried out.",
		Recommendations: []string{
			"Having BGP exposed to non-partiticaping host is considered a bad security practice.",
		},
		References: []string{
			"https://tools.ietf.org/html/bcp194#section-4",
		},
	}
)

func tcpConnect(target string, port int) error {

	targetAddr := target + ":" + strconv.Itoa(port)
	if _, err := net.ResolveTCPAddr("tcp", targetAddr); err != nil {
		return err
	}

	conn, err := net.DialTimeout("tcp", targetAddr, defaultTimeout)
	if err != nil {
		return err
	}

	if err := conn.Close(); err != nil {
		return err
	}

	return nil
}

func main() {

	run := func(ctx context.Context, target, assetType, optJSON string, state checkstate.State) (err error) {
		logger.Printf("Starting the %v check", checkName)

		if target == "" {
			return errors.New("invalid hostname provided")
		}

		isReachable, err := helpers.IsReachable(target, assetType, nil)
		if err != nil {
			logger.Warnf("Can not check asset reachability: %v", err)
		}
		if !isReachable {
			return checkstate.ErrAssetUnreachable
		}

		if err := tcpConnect(target, defaultBGPPort); err == nil {
			state.AddVulnerabilities(exposedBGP)
		} else {
			state.Notes = err.Error()
		}

		return nil
	}
	c := check.NewCheckFromHandler(checkName, run)

	c.RunAndServe()
}
