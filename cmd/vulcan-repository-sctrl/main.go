/*
Copyright 2024 Adevinta
*/

package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"time"

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
		Resources: []report.ResourcesGroup{
			{
				Name: "Security Controls",
				Header: []string{
					"Control",
					"Path",
					"Link",
				},
				Rows: []map[string]string{},
			},
		},
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

		repoPath, repoBranch, err := helpers.CloneGitRepositoryContext(ctx, target, opt.Branch, opt.Depth)
		defer os.RemoveAll(repoPath) // nolint: errcheck
		if err != nil {
			return err
		}

		v := securityControlFound
		v.AffectedResource = target

		// Run semgrep.
		logger.Info("running semgrep")
		semgrepTS := time.Now().Unix()
		r, err := runSemgrep(ctx, logger, opt.Timeout, opt.RuleConfigPath, repoPath)
		if err != nil {
			return err
		}
		semgrepFindingResources := semgrepFindings(logger, r, target, repoPath, repoBranch)
		v.Resources[0].Rows = append(v.Resources[0].Rows, semgrepFindingResources...)
		logger.WithField("semgrep_took", time.Since(time.Unix(semgrepTS, 0)).Seconds()).Info("semgrep took")

		// Check for dependabot.
		logger.Info("checking dependabot")
		dependabotTS := time.Now().Unix()
		dependabotResource, err := checkDependabot(ctx, logger, target)
		if err != nil {
			logger.WithError(err).Error("could not get repository security information")
			if len(v.Resources[0].Rows) > 0 {
				logger.Warn("dependabot check failed, but skipping error because other security controls were found")
			} else {
				return err
			}
		}
		v.Resources[0].Rows = append(v.Resources[0].Rows, dependabotResource...)
		logger.WithField("dependabot_took", time.Since(time.Unix(dependabotTS, 0)).Seconds()).Info("dependabot took")

		// No security controls found. Reporting missing security controls vulnerability.
		if len(v.Resources[0].Rows) == 0 {
			v = missingSecurityControls
			v.AffectedResource = target
		}

		state.AddVulnerabilities(v)
		return nil
	}

	c := check.NewCheckFromHandler(checkName, run)
	c.RunAndServe()
}
