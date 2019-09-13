package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"

	"github.com/adevinta/vulcan-check-sdk"
	"github.com/adevinta/vulcan-check-sdk/state"
	"github.com/adevinta/vulcan-report"
)

var (
	checkName = "vulcan-mx"

	// MXIsPresent is a check name
	MXIsPresent = report.Vulnerability{
		Summary:     "MX presence",
		Description: "This domain has at least one MX record.",
		Score:       report.SeverityThresholdNone,
		Recommendations: []string{
			"It is recommended to run DMARC, DKIM and SPF checks for each domain that contain MX records.",
		},
	}
)

// MXJson is used for storing MX Records (results of lookupMX)
type MXJson struct {
	MXRecords []MXRecord `json:"mx_records"`
}

// MXRecord is used for storing single result from []*net.MX
type MXRecord struct {
	Host string `json:"host"`
	Pref uint16 `json:"pref"`
}

func lookupMX(host string) ([]*net.MX, error) {
	records, err := net.LookupMX(host)
	if err != nil {
		return nil, err
	}
	return records, nil
}

func main() {

	run := func(ctx context.Context, target string, optJSON string, state state.State) (err error) {
		if net.ParseIP(target) != nil {
			return errors.New("invalid hostname provided")
		}

		records, err := lookupMX(target)
		if err != nil {
			return
		}

		if len(records) > 0 {
			mxRecords := make([]MXRecord, len(records))
			for i, v := range records {
				mxRecords[i].Host = v.Host
				mxRecords[i].Pref = v.Pref
			}
			state.AddVulnerabilities(MXIsPresent)

			mxJSON := &MXJson{
				MXRecords: mxRecords,
			}
			data, err := json.Marshal(mxJSON)
			if err != nil {
				return err
			}
			state.Notes = string(data)
		}

		return nil
	}
	c := check.NewCheckFromHandler(checkName, run)

	c.RunAndServe()
}
