package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	check "github.com/adevinta/vulcan-check-sdk"
	"github.com/adevinta/vulcan-check-sdk/helpers"
	checkstate "github.com/adevinta/vulcan-check-sdk/state"
	report "github.com/adevinta/vulcan-report"
	"github.com/sirupsen/logrus"
)

const (
	DefaultDepth = 1
	checkName    = "vulcan-repository-sctrl"
)

var (
	missingSecurityControls = report.Vulnerability{
		CWEID:         693,
		Summary:       "Repository missing security controls",
		ImpactDetails: "A repository lacking security controls can lead to expose sensitive information, enable unauthorized access, and other security risks.",
		Score:         report.SeverityThresholdMedium,
		Recommendations: []string{
			"Add a security scanner to your CI/CD pipeline to detect security issues in your codebase.",
			"If you don't have any default scanner, consider using Lava action in your CI/CD pipeline.",
		},
		References: []string{
			"https://github.mpi-internal.com/adevinta/lava-action",
			"https://github.mpi-internal.com/spt-security/lava-internal-action",
		},
		Labels: []string{"potential", "security-control", "repository"},
	}

	securityControlFound = report.Vulnerability{
		Summary: "Security control detected in repository",
		Score:   report.SeverityThresholdNone,
		Labels:  []string{"informational", "security-control", "repository"},
	}
)

type options struct {
	Depth          int    `json:"depth"`
	Branch         string `json:"branch"`
	RuleConfigPath string `json:"rule_config_path"`
	Timeout        int    `json:"timeout"`
}

func main() {
	run := func(ctx context.Context, target, assetType, optJSON string, state checkstate.State) error {
		var err error
		logger := check.NewCheckLogFromContext(ctx, checkName)
		if target == "" {
			return errors.New("check target missing")
		}

		logger = logger.WithFields(logrus.Fields{
			"asset_type": assetType,
		})

		opt := options{}
		if optJSON != "" {
			if err := json.Unmarshal([]byte(optJSON), &opt); err != nil {
				return err
			}
		}
		if opt.Depth == 0 {
			opt.Depth = DefaultDepth
		}

		logger.WithFields(logrus.Fields{"options": opt}).Debug("using options")

		repoPath, repoBranch, err := helpers.CloneGitRepository(target, opt.Branch, opt.Depth)
		if err != nil {
			return err
		}
		defer os.RemoveAll(repoPath)

		r, err := runSemgrep(ctx, logger, opt.Timeout, opt.RuleConfigPath, repoPath)
		if err != nil {
			return err
		}

		addVulnsToState(logger, state, r, target, repoPath, repoBranch)

		return nil
	}

	c := check.NewCheckFromHandler(checkName, run)
	c.RunAndServe()
}

func addVulnsToState(logger *logrus.Entry, state checkstate.State, r *SemgrepOutput, target, repo, branch string) {
	if r == nil || len(r.Results) < 1 {
		logger.Info("no security controls found")
		v := missingSecurityControls
		v.AffectedResource = target
		state.AddVulnerabilities(v)
		return
	}

	logger.WithFields(logrus.Fields{"num_results": len(r.Results)}).Info("security controls found. Processing results")

	v := securityControlFound
	v.AffectedResource = target
	v.Resources = []report.ResourcesGroup{
		{
			Name: "Security Controls",
			Header: []string{
				"Control",
				"Path",
				"Link",
			},
			Rows: []map[string]string{},
		},
	}

	for _, result := range r.Results {
		filepath := strings.TrimPrefix(result.Path, fmt.Sprintf("%s/", repo))
		path := fmt.Sprintf("%s:%d", filepath, result.Start.Line)
		link := strings.TrimSuffix(target, ".git") + "/blob/" + branch + "/" + filepath + "#L" + fmt.Sprint(result.Start.Line)
		row := map[string]string{
			"Control": result.Extra.Message,
			"Path":    path,
			"Link":    fmt.Sprintf("(Link)[%s]", link),
		}
		v.Resources[0].Rows = append(v.Resources[0].Rows, row)
	}
	sort.Slice(v.Resources[0].Rows, func(i, j int) bool {
		return v.Resources[0].Rows[i]["Path"] < v.Resources[0].Rows[j]["Path"]
	})

	v.Fingerprint = helpers.ComputeFingerprint(v.Resources[0].Rows)

	state.AddVulnerabilities(v)
}
