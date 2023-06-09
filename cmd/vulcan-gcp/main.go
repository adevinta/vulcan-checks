/*
Copyright 2019 Adevinta
*/

package main

import (
	"context"
	"fmt"

	check "github.com/adevinta/vulcan-check-sdk"
	"github.com/adevinta/vulcan-check-sdk/helpers"
	"github.com/adevinta/vulcan-check-sdk/state"
	report "github.com/adevinta/vulcan-report"
)

var (
	checkName = "vulcan-gcp"
	logger    = check.NewCheckLog(checkName)
)

func main() {
	c := check.NewCheckFromHandler(checkName, run)
	c.RunAndServe()
}

func run(ctx context.Context, target, assetType, optJSON string, state state.State) (err error) {
	logger.Printf("Starting the %v check", checkName)
	logger.Printf("Validating params. Target: %v Options: %v ...", target, optJSON)

	state.AddVulnerabilities(report.Vulnerability{
		AffectedResource: target,
		Labels:           []string{"issue", checkName},
		Fingerprint:      helpers.ComputeFingerprint(),
		Summary:          "Example",
		Description:      fmt.Sprintf("Description vulnerability in %s", assetType),
		Details:          fmt.Sprintf("Details vulnerability in %s", assetType),
		Score:            report.SeverityThresholdMedium,
	})
	return nil
}
