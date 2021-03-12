/*
Copyright 2021 Adevinta
*/

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"

	check "github.com/adevinta/vulcan-check-sdk"
	"github.com/adevinta/vulcan-check-sdk/helpers"
	checkstate "github.com/adevinta/vulcan-check-sdk/state"
	report "github.com/adevinta/vulcan-report"
	seekret "github.com/apuigsech/seekret"
	sourcedir "github.com/apuigsech/seekret-source-dir"
	"github.com/apuigsech/seekret/models"
	git "gopkg.in/src-d/go-git.v4"
	http "gopkg.in/src-d/go-git.v4/plumbing/transport/http"
)

type options struct {
	Depth int `json:"depth"`
}

var (
	checkName    = "vulcan-seekret"
	logger       = check.NewCheckLog(checkName)
	leakedSecret = report.Vulnerability{
		Summary:       "Secrets Leaked in Git Repository",
		Description:   "Some secrets have been found stored in the Git repository. These secrets may be in any historical commit and could be retrieved by anyone with read access to the repository. Test data and false positives can be marked as exceptions so that they are only reported informationally as documented in the references section.",
		CWEID:         540,
		Score:         report.SeverityThresholdNone,
		ImpactDetails: "Anyone with access to the repository could retrieve the leaked secrets and use them the future with malicious intent.",
		Recommendations: []string{
			"Completely remove the secrets from the repository as explained in the references.",
			"Encrypt the secrets using a tool like AWS Secrets Manager, Strongbox or Vault.",
			"Use a \"vulcan-exceptions.yaml\" file as described in the references.",
		},
		References: []string{
			"https://help.github.com/en/articles/removing-sensitive-data-from-a-repository",
			"https://github.com/apuigsech/seekret#exceptions",
		},
	}

	rulesPath   = "/opt/rules/"
	ignoredDirs = []string{
		// JavaScript
		"(^|/)node_modules/.*",
		"(^|/)bower_components/.*",
		// Ruby
		"(^|/)bundler/.*",
		// Go
		"(^|/)vendor/.*",
		"(^|/)testdata/.*",
		// Documentation
		"(^|/)docs?/.*",
	}
)

func main() {
	run := func(ctx context.Context, target, assetType, optJSON string, state checkstate.State) (err error) {
		if target == "" {
			return errors.New("check target missing")
		}

		var opt options
		opt.Depth = 1
		if optJSON != "" {
			if err := json.Unmarshal([]byte(optJSON), &opt); err != nil {
				return err
			}
		}

		// We check if the target is not the public Github.
		targetURL, err := url.Parse(target)
		if err != nil {
			return err
		}

		// TODO: Support multiple authenticated Github Enterprise instances.
		githubURL, err := url.Parse(os.Getenv("GITHUB_ENTERPRISE_ENDPOINT"))
		if err != nil {
			return err
		}

		var auth *http.BasicAuth
		if githubURL.Host != "" && targetURL.Host == githubURL.Host {
			auth = &http.BasicAuth{
				Username: "username", // Can be anything except blank.
				Password: os.Getenv("GITHUB_ENTERPRISE_TOKEN"),
			}
		}

		gitCreds := &helpers.GitCreds{}
		if auth != nil {
			gitCreds.User = auth.Username
			gitCreds.Pass = auth.Password
		}
		isReachable, err := helpers.IsReachable(target, assetType, gitCreds)
		if err != nil {
			logger.Warnf("Can not check asset reachability: %v", err)
		}
		if !isReachable {
			return checkstate.ErrAssetUnreachable
		}

		repoPath := filepath.Join("/tmp", filepath.Base(targetURL.Path))
		if err := os.Mkdir(repoPath, 0755); err != nil {
			return err
		}

		_, err = git.PlainClone(repoPath, false, &git.CloneOptions{
			URL:   target,
			Auth:  auth,
			Depth: opt.Depth,
		})
		if err != nil {
			return err
		}

		s := seekret.NewSeekret()

		ruleScores, err := loadRuleScoresFromDir(rulesPath)
		if err != nil {
			return err
		}

		s.LoadRulesFromDir(rulesPath, true)
		s.LoadObjects(
			sourcedir.SourceTypeDir,
			repoPath,
			map[string]interface{}{
				"hidden":    true,
				"recursive": true,
			},
		)

		for _, dirName := range ignoredDirs {
			s.AddException(models.Exception{
				Object: regexp.MustCompile(dirName),
			})
		}
		s.LoadExceptionsFromFile(filepath.Join(repoPath, "vulcan-exceptions.yaml"))

		s.Inspect(10)
		secrets := s.ListSecrets()

		if len(secrets) > 0 {
			vuln := leakedSecret

			leakedSecrets := report.ResourcesGroup{
				Name: "Leaked Secrets",
				Header: []string{
					"Rule",
					"File",
					"Line Number",
					"Line Summary",
					"Exception",
				},
			}

			for _, secret := range secrets {
				objectPath, err := filepath.Rel(repoPath, secret.Object.Name)
				if err != nil {
					continue
				}

				// Truncate line to 30 characters and replace non-printable characters with "?".
				// This is done to avoid both processing and presentation issues.
				lineSummary := ""
				for i := range secret.Line {
					if i >= 30 {
						lineSummary += "..."
						break
					}

					char := rune(secret.Line[i])
					if char > unicode.MaxASCII || !unicode.IsPrint(char) {
						lineSummary += "?"
					} else {
						lineSummary += string(char)
					}
				}

				ruleScore := float32(report.SeverityThresholdHigh)
				if !secret.Exception {
					shortRuleName := strings.Split(secret.Rule.Name, ".")[1]
					if score, ok := ruleScores[shortRuleName]; ok {
						ruleScore = score
					}

					if ruleScore > vuln.Score {
						vuln.Score = ruleScore
					}
				}

				leakedSecrets.Rows = append(leakedSecrets.Rows,
					map[string]string{
						"Rule":         secret.Rule.Name,
						"Severity":     fmt.Sprintf("%.1f", ruleScore),
						"File":         objectPath,
						"Line Number":  fmt.Sprintf("%d", secret.Nline),
						"Line Summary": lineSummary,
						"Exception":    fmt.Sprintf("%v", secret.Exception),
					},
				)

			}

			if len(leakedSecrets.Rows) > 0 {
				vuln.Resources = []report.ResourcesGroup{leakedSecrets}
				state.AddVulnerabilities(vuln)
			}
		}

		return nil
	}

	c := check.NewCheckFromHandler(checkName, run)

	c.RunAndServe()
}
