package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"strings"

	"github.com/adevinta/vulcan-check-sdk/helpers/command"
)

const (
	prowlerCmd   = `/prowler/prowler`
	reportFormat = `json`
)

type prowlerReport struct {
	entries []entry
}

type entry struct {
	Profile   string
	Account   string
	Control   string
	Message   string
	Status    string
	Scored    string
	Level     string
	ControlID string `json:"Control ID"`
	Region    string
	Timestamp string
}

/*
	Command example:
		prowler -r eu-west-1 -g cislevel1 -T 3600 -M json
*/

func buildParams(opts options) []string {
	return []string{
		"-r", opts.Region,
		"-g", strings.Join(opts.Groups, ","),
		"-M", reportFormat,
	}
}

func runProwler(ctx context.Context, opts options) (*prowlerReport, error) {
	logger.Infof("using options: %#v", opts)
	params := buildParams(opts)

	version, _, err := command.Execute(ctx, logger, prowlerCmd, "-V")
	if err != nil {
		return nil, err
	}
	logger.Infof("prowler version: %s", version)

	output, status, err := command.Execute(ctx, logger, prowlerCmd, params...)
	if err != nil {
		return nil, err
	}
	logger.Infof("exit status: %v", status)
	logger.Debugf("prowler output: %s", output)

	var report prowlerReport
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		var e entry
		if err := json.Unmarshal([]byte(scanner.Text()), &e); err != nil {
			return nil, err
		}
		report.entries = append(report.entries, e)
	}
	return &report, nil
}
