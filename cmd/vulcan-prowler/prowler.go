/*
Copyright 2020 Adevinta
*/

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/adevinta/vulcan-check-sdk/helpers/command"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/sirupsen/logrus"
)

const (
	prowlerCmd     = `/prowler/prowler`
	reportFormat   = `json`
	reportName     = `report`
	reportLocation = `/prowler/output/report.json`
)

type prowlerReport struct {
	entries []entry
}

type entry struct {
	Profile    string
	Account    string `json:"Account Number"`
	Control    string
	Message    string
	Status     string
	Scored     string
	Level      string
	ControlID  string `json:"Control ID"`
	Region     string
	Timestamp  string
	Compliance string
	Service    string
}

/*
	Command example:
		prowler -r eu-west-1 -g cislevel1 -T 3600 -M json -F report

	Output available at /prowler/output/report.json
*/

func buildParams(region string, groups []string) []string {
	params := []string{
		"-g", strings.Join(groups, ","),
		"-M", reportFormat,
		"-F", reportName,
	}
	if region != "" {
		params = append(params, "-r", region, "-f", region)
	} else {
		params = append(params, "-r", defaultAPIRegion)
	}
	return params
}

func runProwler(ctx context.Context, logger *logrus.Entry, cfg aws.Credentials, region string, groups []string) (*prowlerReport, error) {
	logger.Infof("using region: %+v, and groups: %+v", region, groups)
	params := buildParams(region, groups)

	version, _, err := command.Execute(ctx, logger, prowlerCmd, "-V")
	if err != nil {
		return nil, err
	}
	logger.Infof("prowler version: %s", version)

	env := []string{
		fmt.Sprintf("%s=%s", envKeyID, cfg.AccessKeyID),
		fmt.Sprintf("%s=%s", envKeySecret, cfg.SecretAccessKey),
		fmt.Sprintf("%s=%s", envToken, cfg.SessionToken),
	}
	output, status, err := command.ExecuteEnv(ctx, logger, env, prowlerCmd, params...)
	if err != nil {
		return nil, err
	}
	logger.Infof("exit status: %v", status)
	logger.Debugf("prowler output: %s", output)

	fileReport, err := os.ReadFile(reportLocation)
	if err != nil {
		return nil, err
	}
	logger.Debugf("file report: %s", fileReport)

	scanner := bufio.NewScanner(bytes.NewReader(fileReport))
	var report prowlerReport
	for scanner.Scan() {
		var e entry
		if err := json.Unmarshal([]byte(scanner.Text()), &e); err != nil {
			logger.Errorf("output line: %v", scanner.Text())
			return nil, err
		}
		report.entries = append(report.entries, e)
	}

	return &report, nil
}
