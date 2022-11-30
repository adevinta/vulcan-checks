/*
Copyright 2022 Adevinta
*/
package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	check "github.com/adevinta/vulcan-check-sdk"
	checkstate "github.com/adevinta/vulcan-check-sdk/state"
	"github.com/adevinta/vulcan-checks/cmd/vulcan-blast-radius/securitygraph"
	report "github.com/adevinta/vulcan-report"
)

var (
	name            = "vulcan-blast-radius"
	logger          = check.NewCheckLog(name)
	blastRadiusVuln = report.Vulnerability{
		Summary:     "Blast Radius Score: %.2f",
		Description: "Gives an idea about how many resources are in danger to be compromised if an asset is itself compromised.",
		Score:       report.SeverityThresholdNone,
		Recommendations: []string{
			"The higher the score, the higher the number of resources an asset can potentially grant access to if compromised.",
			"Try to limit the number of resources that an asset has access to the minimum.",
			"Pay extra attention to the security of the assets with high blast radius.",
		},
		Labels: []string{"blast-radius"},
	}
	ErrNoIntelAPIBaseURL = errors.New("no base url for the Intel API was provided")
)

// intelAPI defines the interface that an IntelAPI client must implement to be
// able to be used by the check. This interface in introduced to make easier to
// test the check.
type intelAPI interface {
	BlastRadius(req securitygraph.BlastRadiusRequest) (securitygraph.BlastRadiusResponse, error)
}

func main() {
	// Using a runner function as a wrapper of the function actually running
	// the check allows us to specify an alternative implementation of the
	// intelAPIClient in the tests.
	runner := func(ctx context.Context, target, assetType, optJSON string, state checkstate.State) error {
		return run(ctx, target, assetType, optJSON, state, nil)
	}
	c := check.NewCheckFromHandler(name, runner)
	c.RunAndServe()
}

// run implements the Blast Radius check.
func run(ctx context.Context, target, assetType, optJSON string, state checkstate.State, intelAPIClient intelAPI) (err error) {
	logger.Printf("Starting the %v check", name)
	if target == "" {
		return errors.New("no hostname or IP address provided")
	}
	// If no intel API client was provided create it using the default
	// implementation.
	if intelAPIClient == nil {
		base := os.Getenv("INTEL_API_URL")
		if base == "" {
			return ErrNoIntelAPIBaseURL
		}
		insecure := os.Getenv("INTEL_API_INSECURE_SKIP_VERIFY") == "1"
		client, err := securitygraph.NewIntelAPIClient(base, insecure)
		if err != nil {
			return fmt.Errorf("error creating the Intel API client: %w", err)
		}
		intelAPIClient = client
	}
	req := securitygraph.BlastRadiusRequest{
		AssetIdentifier: target,
		AssetType:       assetType,
	}
	resp, err := intelAPIClient.BlastRadius(req)

	vuln := blastRadiusVuln
	if errors.Is(err, securitygraph.ErrAssetDoesNotExist) || errors.Is(err, securitygraph.ErrNotEnoughInfo) {
		vuln.Summary = "Blast Radius Score: Unknown"
		vuln.Details = err.Error()
		state.AddVulnerabilities(vuln)
		return nil
	}
	intelErr := securitygraph.HttpStatusError{}
	if errors.As(err, &intelErr) && intelErr.Status == 500 {
		vuln.Summary = "Blast Radius Score: Unknown"
		details := fmt.Sprintf("There was an error calculating the blast radius: %v", err)
		vuln.Details = details
		state.AddVulnerabilities(vuln)
		return nil
	}
	if err != nil {
		return err
	}
	vuln.Summary = fmt.Sprintf(blastRadiusVuln.Summary, resp.Score)
	vuln.Details = resp.Metadata
	state.AddVulnerabilities(vuln)
	return nil
}
