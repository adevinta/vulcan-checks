// Copyright 2024 Adevinta

// Vulcan-govulncheck uses govulncheck to report known vulnerabilities
// that affect Go code.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"

	check "github.com/adevinta/vulcan-check-sdk"
	"github.com/adevinta/vulcan-check-sdk/helpers"
	checkstate "github.com/adevinta/vulcan-check-sdk/state"
	report "github.com/adevinta/vulcan-report"
	"github.com/jroimartin/sarif"
	"github.com/sirupsen/logrus"
)

const (
	checkName    = "vulcan-govulncheck"
	defaultDepth = 1
)

var (
	logger = check.NewCheckLog(checkName)
)

type options struct {
	Depth  int    `json:"depth"`
	Branch string `json:"branch"`

	// Govulncheck args.

	ChDir    string `json:"dir"`      // -C flag
	DB       string `json:"db"`       // -db flag
	Mode     string `json:"mode"`     // -mode flag
	Scan     string `json:"scan"`     // -scan flag
	Tags     string `json:"tags"`     // -tags flag
	Test     string `json:"test"`     // -test flag
	Patterns string `json:"patterns"` // patterns argument
}

func main() {
	c := check.NewCheckFromHandler(checkName, run)
	c.RunAndServe()
}

func run(ctx context.Context, target, assetType, optJSON string, state checkstate.State) error {
	if target == "" {
		return errors.New("check target missing")
	}

	logger = logger.WithFields(logrus.Fields{
		"target":     target,
		"asset_type": assetType,
	})
	logger.Logger.SetLevel(logrus.DebugLevel)

	var opt options
	if optJSON != "" {
		if err := json.Unmarshal([]byte(optJSON), &opt); err != nil {
			return fmt.Errorf("decode options: %w", err)
		}
	}

	if opt.Depth == 0 {
		opt.Depth = defaultDepth
	}

	logger.WithFields(logrus.Fields{"options": opt}).Debug("using options")

	repoPath, branchName, err := helpers.CloneGitRepository(target, opt.Branch, opt.Depth)
	logger.WithFields(logrus.Fields{"repo_path": repoPath, "branch_name": branchName, "err": err}).Debug("cloned repository")
	if err != nil {
		return fmt.Errorf("clone git repository: %w", err)
	}

	if err := runGovulncheck(ctx, logger, repoPath, opt, state); err != nil {
		return fmt.Errorf("run govulncheck: %w", err)
	}

	return nil
}

func runGovulncheck(ctx context.Context, logger *logrus.Entry, dir string, opt options, state checkstate.State) error {
	args := []string{"-format", "sarif"}
	if opt.ChDir != "" {
		args = append(args, "-C", opt.ChDir)
	}
	if opt.DB != "" {
		args = append(args, "-db", opt.DB)
	}
	if opt.Mode != "" {
		args = append(args, "-mode", opt.Mode)
	}
	if opt.Scan != "" {
		args = append(args, "-scan", opt.Scan)
	}
	if opt.Tags != "" {
		args = append(args, "-tags", opt.Tags)
	}
	if opt.Test != "" {
		args = append(args, "-test", opt.Test)
	}
	if opt.Patterns != "" {
		args = append(args, opt.Patterns)
	}

	logger.WithFields(logrus.Fields{"args": args}).Debug("running govulncheck")

	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, "govulncheck", args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cmd.Dir = dir
	if err := cmd.Run(); err != nil {
		logger.WithFields(logrus.Fields{"err": err, "stderr": stderr.String()}).Error("run command")
		return fmt.Errorf("run command: %w: %q", err, stderr.String())
	}

	vulns, err := parseSarif(&stdout)
	if err != nil {
		return fmt.Errorf("parse sarif: %w", err)
	}

	for _, vuln := range vulns {
		state.ResultData.Vulnerabilities = append(state.ResultData.Vulnerabilities, vuln)
		logger.WithFields(logrus.Fields{"vuln": vuln}).Debug("found vulnerability")
	}

	return nil
}

func parseSarif(r io.Reader) ([]report.Vulnerability, error) {
	var doc sarif.Log
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		return nil, fmt.Errorf("decode SARIF document: %w", err)
	}

	var vulns []report.Vulnerability
	for _, run := range doc.Runs {
		for _, result := range run.Results {
			vuln, err := parseResult(doc, result)
			if err != nil {
				return nil, fmt.Errorf("parse result: %w", err)
			}
			vulns = append(vulns, vuln)
		}
	}
	return vulns, nil
}

func parseResult(doc sarif.Log, result sarif.Result) (report.Vulnerability, error) {
	rule, found := doc.FindRule(result.RuleID)
	if !found {
		return report.Vulnerability{}, fmt.Errorf("unknown rule: %v", result.RuleID)
	}

	var rscs []report.ResourcesGroup
	for _, cf := range result.CodeFlows {
		rsc := report.ResourcesGroup{
			Name:   cf.Message.Text,
			Header: []string{"module", "location", "function"},
		}
		for _, tf := range cf.ThreadFlows {
			for _, loc := range tf.Locations {
				row := make(map[string]string)
				row["module"] = loc.Module
				row["location"] = loc.Location.PhysicalLocation.String()
				row["function"] = loc.Location.Message.Text
				rsc.Rows = append(rsc.Rows, row)
			}
		}
		rscs = append(rscs, rsc)
	}

	location := getLocations(result)
	vuln := report.Vulnerability{
		Summary:          rule.ShortDescription.Text,
		Score:            calcScore(result),
		AffectedResource: location,
		Fingerprint:      helpers.ComputeFingerprint(result.RuleID, location),
		CWEID:            937,
		Description:      rule.FullDescription.Text,
		Details:          result.Message.Text,
		Labels:           []string{"issue"},
		Recommendations: []string{
			"Visit the linked references for more details.",
		},
		References: []string{rule.HelpURI},
		Resources:  rscs,
	}

	return vuln, nil
}

func getLocations(result sarif.Result) string {
	var locs []string
	for _, loc := range result.Locations {
		locs = append(locs, loc.PhysicalLocation.String())
	}
	return strings.Join(locs, " ")
}

func calcScore(result sarif.Result) float32 {
	if result.Level == "error" {
		return 8 // high severity
	} else {
		return 0 // informational severity
	}
}
