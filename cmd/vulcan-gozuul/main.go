package main

import (
	"context"
	"errors"

	gozuul "github.com/adevinta/gozuul"
	check "github.com/adevinta/vulcan-check-sdk"
	"github.com/adevinta/vulcan-check-sdk/state"
	report "github.com/adevinta/vulcan-report"
)

const (
	checkName = "vulcan-gozuul"
)

var (
	// NOTE: should we increase to critical?
	gozuulVuln = report.Vulnerability{
		CWEID:           434,
		Summary:         "Remote Code Exeucition in Zuul",
		Description:     "Zuul was configured with zuul.filter.admin.enabled to True, which can be used to upload filters via the default application port which may result in Remote Code Execution (RCE).",
		Score:           report.SeverityThresholdHigh,
		ImpactDetails:   "Allows remote attackers to execute code in the server via uploading a malicious filter.",
		References:      []string{"https://github.com/Netflix/security-bulletins/blob/master/advisories/nflx-2016-003.md"},
		Recommendations: []string{"Ensure the property ZUUL_FILTER_ADMIN_ENABLED is set to False."},
	}
)

func main() {
	run := func(ctx context.Context, target string, optJSON string, state state.State) (err error) {
		if target == "" {
			return errors.New("check target missing")
		}
		res, err := gozuul.PassiveScan(target)
		if err != nil {
			return err
		}

		if res.Vulnerable {
			state.AddVulnerabilities(gozuulVuln)
		}

		return nil
	}

	c := check.NewCheckFromHandler(checkName, run)
	c.RunAndServe()
}
