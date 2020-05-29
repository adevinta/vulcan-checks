package main

import (
	"context"
	"encoding/json"

	"github.com/sirupsen/logrus"

	check "github.com/adevinta/vulcan-check-sdk"
	"github.com/adevinta/vulcan-check-sdk/state"
	report "github.com/adevinta/vulcan-report"
)

type options struct {
	// TCP connection timeout.
	Timeout int `json:"timeout"`
	// TCP port to scan.
	Port string `json:"port"`
}

var (
	checkName      = "vulcan-check"
	defaultPort    = "3389"
	defaultTimeout = 2

	exposed = report.Vulnerability{
		Summary:         "Exposed Port",
		Description:     "The service is vulnerable it may allow external attackers to gain access to the host.",
		Score:           report.SeverityThresholdMedium,
		Recommendations: []string{"Block access."},
	}

	logger *logrus.Entry
)

func isExposed(host, port string, timeout int) []report.Vulnerability {
	isExposed := false

	if isExposed {
		return []report.Vulnerability{exposed}
	}

	return nil
}

func run(ctx context.Context, target string, optJSON string, state state.State) (err error) {
	l := check.NewCheckLog(checkName)
	logger = l.WithFields(logrus.Fields{"target": target, "options": optJSON})

	var opt options
	if optJSON != "" {
		if err = json.Unmarshal([]byte(optJSON), &opt); err != nil {
			return err
		}
	}

	if opt.Timeout == 0 {
		opt.Timeout = defaultTimeout
	}

	if opt.Port == "" {
		opt.Port = defaultPort
	}

	vulns := isExposed(target, opt.Port, opt.Timeout)
	state.AddVulnerabilities(vulns...)

	return nil
}

func main() {
	c := check.NewCheckFromHandler(checkName, run)
	c.RunAndServe()
}
