/*
Copyright 2019 Adevinta
*/

package main

import (
	"context"
	"fmt"
	"net"

	check "github.com/adevinta/vulcan-check-sdk"
	"github.com/adevinta/vulcan-check-sdk/helpers"
	checkstate "github.com/adevinta/vulcan-check-sdk/state"
	report "github.com/adevinta/vulcan-report"
)

var (
	checkName = "vulcan-mx"
	logger    = check.NewCheckLog(checkName)

	// MXIsPresent is a check name
	MXIsPresent = report.Vulnerability{
		Summary:     "MX presence",
		Description: "This domain has at least one MX record.",
		Score:       report.SeverityThresholdNone,
		Recommendations: []string{
			"It is recommended to run DMARC, DKIM and SPF checks for each domain that contain MX records.",
		},
		Labels:      []string{"issue", "discovery"},
		Fingerprint: helpers.ComputeFingerprint(),
	}
)

func main() {
	run := func(ctx context.Context, target, assetType, optJSON string, state checkstate.State) (err error) {
		isReachable, err := helpers.IsReachable(target, assetType, nil)
		if err != nil {
			logger.Warnf("Can not check asset reachability: %v", err)
		}
		if !isReachable {
			return checkstate.ErrAssetUnreachable
		}
		records, _ := net.LookupMX(target)
		if len(records) > 0 {
			gr := report.ResourcesGroup{
				Name: "MX Records",
				Header: []string{
					"Host",
					"Pref",
				},
			}
			for _, v := range records {
				row := map[string]string{
					"Host": v.Host,
					"Pref": fmt.Sprintf("%d", v.Pref),
				}
				gr.Rows = append(gr.Rows, row)
			}
			MXIsPresent.Resources = []report.ResourcesGroup{gr}
			MXIsPresent.AffectedResource = target
			state.AddVulnerabilities(MXIsPresent)
		}
		return nil
	}
	c := check.NewCheckFromHandler(checkName, run)
	c.RunAndServe()
}
