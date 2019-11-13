package main

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"

	check "github.com/adevinta/vulcan-check-sdk"
	"github.com/adevinta/vulcan-check-sdk/state"
	report "github.com/adevinta/vulcan-report"
	seekret "github.com/apuigsech/seekret"
	sourcedir "github.com/apuigsech/seekret-source-dir"
	"github.com/apuigsech/seekret/models"
	git "gopkg.in/src-d/go-git.v4"
	http "gopkg.in/src-d/go-git.v4/plumbing/transport/http"
)

var (
	checkName    = "vulcan-seekret"
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
	run := func(ctx context.Context, target string, optJSON string, state state.State) (err error) {
		if target == "" {
			return errors.New("check target missing")
		}

		// We check if the target is in Adevinta's GHE.
		targetURL, err := url.Parse(target)
		if err != nil {
			return err
		}

		var auth *http.BasicAuth
		if targetURL.Host == "github.mpi-internal.com" {
			auth = &http.BasicAuth{
				Username: "username", // Can be anything except blank.
				Password: os.Getenv("GITHUB_ENTERPRISE_TOKEN"),
			}
		}

		repoPath := filepath.Join("/tmp", filepath.Base(targetURL.Path))
		if err := os.Mkdir(repoPath, 0755); err != nil {
			return err
		}

		_, err = git.PlainClone(repoPath, false, &git.CloneOptions{
			URL:  target,
			Auth: auth,
		})
		if err != nil {
			return err
		}

		s := seekret.NewSeekret()

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
			leakedSecrets := report.ResourcesGroup{
				Name: "Leaked Secrets",
				Header: []string{
					"Rule",
					"File",
					"Line Number",
					"Line Summary",
				},
			}

			for _, secret := range secrets {
				if secret.Exception {
					continue
				}

				objectPath, err := filepath.Rel(repoPath, secret.Object.Name)
				if err != nil {
					continue
				}

				lineSummary := secret.Line
				if len(lineSummary) > 30 {
					lineSummary = lineSummary[0:29] + "..."
				}

				leakedSecrets.Rows = append(leakedSecrets.Rows,
					map[string]string{
						"Rule":         secret.Rule.Name,
						"File":         objectPath,
						"Line Number":  fmt.Sprintf("%d", secret.Nline),
						"Line Summary": lineSummary,
					},
				)
			}

			if len(leakedSecrets.Rows) > 0 {
				vuln := leakedSecret
				vuln.Score = report.SeverityThresholdHigh
				vuln.Resources = []report.ResourcesGroup{leakedSecrets}
				state.AddVulnerabilities(vuln)
			}
		}

		return nil
	}

	c := check.NewCheckFromHandler(checkName, run)

	c.RunAndServe()
}
