/*
Copyright 2022 Adevinta
*/

// vulcan-blast-radius implements a check that uses the Security Graph to get
// the blast radius of an asset.
package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"html/template"
	"os"

	check "github.com/adevinta/vulcan-check-sdk"
	checkstate "github.com/adevinta/vulcan-check-sdk/state"
	report "github.com/adevinta/vulcan-report"

	"github.com/adevinta/vulcan-checks/cmd/vulcan-blast-radius/intel"
)

const (
	checkName      = "vulcan-blast-radius"
	detailsTxtTemp = `Calculated Blast Radius score: {{ printf "%.2f" .}}`
	summaryTxtTemp = `Blast Radius: {{if not . }}Unknown{{else}}{{.}}{{end}}`
)

var (
	detailsTemplate = template.Must(template.New("").Parse(detailsTxtTemp))
	summaryTemplate = template.Must(template.New("").Parse(summaryTxtTemp))
	blastRadiusVuln = report.Vulnerability{
		Description: "Gives an idea of how many resources are in danger of being compromised if a given asset is compromised.",
		Score:       report.SeverityThresholdNone,
		Recommendations: []string{
			"The higher the score, the higher the number of resources an asset can potentially grant access to if compromised.",
			"Try to minimize the number of accessible resources.",
			"Pay extra attention to the security of the assets with high blast radius.",
		},
		Labels: []string{"blast-radius"},
	}
	// ErrNoIntelAPIBaseURL is returned by check when no url for the intel API
	// is provided.
	ErrNoIntelAPIBaseURL = errors.New("no base url for the Intel API was provided")
)

// intelAPI defines the interface that an IntelAPI client must implement to be
// used by the check. This interface in introduced to make easier to test the
// check.
type intelAPI interface {
	BlastRadius(req intel.BlastRadiusRequest) (intel.BlastRadiusResponse, error)
}

func main() {
	// Wrapping the function running the actual check allows us to specify
	// an alternative implementation of the intelAPIClient interface in tests.
	runner := func(ctx context.Context, target, assetType, optJSON string, state checkstate.State) error {
		return run(ctx, target, assetType, optJSON, state, nil)
	}
	c := check.NewCheckFromHandler(checkName, runner)
	c.RunAndServe()
}

// run implements the Blast Radius check.
func run(ctx context.Context, target, assetType, optJSON string, state checkstate.State, intelAPIClient intelAPI) (err error) {
	logger := check.NewCheckLogFromContext(ctx, checkName)
	logger.Printf("Starting the %v check", checkName)
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
		client, err := intel.NewClient(base, insecure)
		if err != nil {
			return fmt.Errorf("error creating the Intel API client: %w", err)
		}
		intelAPIClient = client
	}
	req := intel.BlastRadiusRequest{
		AssetIdentifier: target,
		AssetType:       assetType,
	}
	resp, err := intelAPIClient.BlastRadius(req)

	vuln := blastRadiusVuln
	if errors.Is(err, intel.ErrAssetDoesNotExist) {
		vuln.Summary = mustTemplateExecute(summaryTemplate, nil)
		vuln.Details = fmt.Sprintf("There was an error calculating the blast radius: %v", err)
		state.AddVulnerabilities(vuln)
		return nil
	}
	intelErr := intel.HTTPStatusError{}
	if errors.As(err, &intelErr) && intelErr.Status == 500 {
		vuln.Summary = mustTemplateExecute(summaryTemplate, nil)
		vuln.Details = fmt.Sprintf("There was an error calculating the blast radius: %v", err)
		state.AddVulnerabilities(vuln)
		return nil
	}
	if err != nil {
		return err
	}

	vuln.Summary = mustTemplateExecute(summaryTemplate, brLevel(resp.Score))
	vuln.Details = mustTemplateExecute(detailsTemplate, resp.Score)
	state.AddVulnerabilities(vuln)
	return nil
}

func brLevel(score float64) string {
	switch {
	case score >= 100:
		return "Very High"
	case score >= 10:
		return "High"
	case score >= 1:
		return "Medium"
	default:
		return "Low"
	}
}

func mustTemplateExecute(tmpl *template.Template, data any) string {
	var buf bytes.Buffer
	err := tmpl.Execute(&buf, data)
	if err != nil {
		panic(nil)
	}
	return buf.String()
}
