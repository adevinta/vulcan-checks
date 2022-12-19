package main

import (
	"context"
	"fmt"

	"github.com/adevinta/vulcan-check-sdk/helpers/command"
	"github.com/sirupsen/logrus"
)

const Cmd = `njsscan`

// NOTE: keep this const block separated to not mess with the iota generated
// values.
const (
	NjsscanStatusOk = iota // This should be always 0.
	NjsscanStatusOkwithVulns
)

var params = []string{"--json"}

// NjsscanOutput and Result represent the output information from the njsscan
// command.  Non-used fields have been intentionally ommitted.
type NjsscanOutput struct {
	Results map[string]NjsscanResult `json:"nodejs"`
	Errors  []interface{}            `json:"errors"`
}

type NjsscanResult struct {
	Files []struct {
		FilePath      string `json:"file_path"`
		MatchLines    []int  `json:"match_lines"`
		MatchPosition []int  `json:"match_position"`
		MatchString   string `json:"match_string"`
	} `json:"files"`
	Metadata struct {
		Cwe         string `json:"cwe"`
		Description string `json:"description"`
		OwaspWeb    string `json:"owasp-web"`
		Severity    string `json:"severity"`
	} `json:"metadata"`
}

func rumNjsscan(ctx context.Context, logger *logrus.Entry, timeout int, exclude []string, ruleset, dir string) (*NjsscanOutput, error) {

	params = append(params, "--missing-controls")
	params = append(params, dir)

	var report NjsscanOutput
	exitCode, err := command.ExecuteAndParseJSON(ctx, logger, &report, Cmd, params...)
	if err != nil {
		return nil, err
	}

	logger.WithFields(logrus.Fields{"exit_code": exitCode, "report": report}).Debug("njsscan command finished")

	switch exitCode {
	case NjsscanStatusOk, NjsscanStatusOkwithVulns:
		return &report, nil
	default:
		err := fmt.Errorf("njsscan failed with exit code %d", exitCode)
		logger.WithError(err).WithFields(logrus.Fields{"errors": report.Errors}).Error("")
		return nil, err
	}
}
