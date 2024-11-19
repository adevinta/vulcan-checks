/*
Copyright 2019 Adevinta
*/

package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strconv"

	check "github.com/adevinta/vulcan-check-sdk"
	"github.com/adevinta/vulcan-check-sdk/state"
)

const checkName = "vulcan-results-load-test"

type options struct {
	RawSizeInKB    int `json:"raw_size"`
	ReportSizeInKB int `json:"report_size"`
}

func main() {
	c := check.NewCheckFromHandler(checkName, run)
	c.RunAndServe()
}

func run(ctx context.Context, target, assetType, optJSON string, state state.State) (err error) {
	logger := check.NewCheckLog(checkName)
	var opt options

	logger.Debug("Validating params")

	if optJSON == "" {
		return errors.New("error: missing required options: raw_size and report_size")
	}
	if err := json.Unmarshal([]byte(optJSON), &opt); err != nil {
		return err
	}

	logger.WithField("raw_data_size_kb", strconv.Itoa(opt.RawSizeInKB)).Debug("Generating random data for raw result")
	rawDummyData := make([]byte, opt.RawSizeInKB*1024)
	_, _ = rand.Read(rawDummyData)
	logger.WithField("raw_report_size_kb", strconv.Itoa(opt.ReportSizeInKB)).Debug("Generating random data for report result")
	reportDummyData := make([]byte, opt.ReportSizeInKB*1024)
	_, _ = rand.Read(reportDummyData)
	// Write the data also in the log so it will be uploaded to the raw dump.
	logger.WithField("report_dummy_data", reportDummyData).Info("Data generated")
	state.Notes = string(reportDummyData)
	return nil
}
