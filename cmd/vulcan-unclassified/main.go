package main

import (
	"context"

	check "github.com/adevinta/vulcan-check-sdk"
	"github.com/adevinta/vulcan-check-sdk/state"
	report "github.com/adevinta/vulcan-report"
)

var (
	checkName        = "vulcan-unclassified"
	unclassifiedVuln = report.Vulnerability{
		Summary:     "Unclassified Vulnerability",
		Description: "Example vulnerability to test the monitoring of unclassified vulnerabilities.",
		Score:       report.SeverityThresholdLow,
	}
)

func main() {
	c := check.NewCheckFromHandler(checkName, run)
	c.RunAndServe()
}

func run(ctx context.Context, target, targetType string, optJSON string, state state.State) (err error) {
	state.AddVulnerabilities(unclassifiedVuln)
	return nil
}
