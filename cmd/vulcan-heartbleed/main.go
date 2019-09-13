package main

import (
	"context"
	"errors"

	"github.com/FiloSottile/Heartbleed/heartbleed"
	"github.com/adevinta/vulcan-check-sdk"
	"github.com/adevinta/vulcan-check-sdk/state"
	"github.com/adevinta/vulcan-report"
)

var (
	checkName  = "vulcan-heartbleed"
	payload    = []byte("VULCAN-PAYLOAD")
	service    = "https"
	skipVerify = true
	// NOTE: should we increase the Score to Critical?
	heartbleedVuln = report.Vulnerability{
		CWEID:   119,
		Summary: "Heartbleed",
		Description: "OpenSSL versions 1.0.1 through 1.0.1f contain a flaw in its implementation of the TLS/DTLS heartbeat functionality." +
			"This flaw allows an attacker to retrieve private memory of an application that uses the vulnerable OpenSSL library in chunks of " +
			" 64k at a time. Note that an attacker can repeatedly leverage the vulnerability to retrieve as many 64k chunks of memory as " +
			"are necessary to retrieve the intended secrets",
		Score: report.SeverityThresholdHigh,
		ImpactDetails: "An attacker may be able to execute arbitrary code, alter the intended control flow, read sensitive information, " +
			"or cause the system to crash.",
		References: []string{
			"http://heartbleed.com/",
			"https://en.wikipedia.org/wiki/Heartbleed",
		},
		Recommendations: []string{"Upgrade OpenSSL to, at least, 1.0.2h or 1.0.1t"},
	}
)

func testHeartbleed(host string) (string, error) {
	out, err := heartbleed.Heartbleed(&heartbleed.Target{HostIp: host, Service: service}, payload, skipVerify)
	if err != nil {
		return "", err
	}

	return out, nil
}

func main() {

	run := func(ctx context.Context, target string, optJSON string, state state.State) (err error) {
		if target == "" {
			return errors.New("check target missing")
		}

		dump, err := testHeartbleed(target)
		if err != nil {
			state.Notes = err.Error()
		}

		if dump != "" {
			state.AddVulnerabilities(heartbleedVuln)
			state.Data = []byte(dump)
		}

		return nil
	}
	c := check.NewCheckFromHandler(checkName, run)

	c.RunAndServe()
}
