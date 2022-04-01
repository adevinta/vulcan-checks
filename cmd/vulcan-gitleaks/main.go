/*
Copyright 2019 Adevinta
*/

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"

	check "github.com/adevinta/vulcan-check-sdk"
	"github.com/adevinta/vulcan-check-sdk/helpers"
	checkstate "github.com/adevinta/vulcan-check-sdk/state"
	report "github.com/adevinta/vulcan-report"
	"github.com/sirupsen/logrus"
	"gopkg.in/src-d/go-git.v4"
	"gopkg.in/src-d/go-git.v4/plumbing"
	"gopkg.in/src-d/go-git.v4/plumbing/transport/http"
)

const (
	DefaultDepth = 1
)

var (
	checkName        = "vulcan-gitleaks"
	logger           = check.NewCheckLog(checkName)
	reportOutputFile = "report.json"
	leakedSecret     = report.Vulnerability{
		Summary:       "Secrets Leaked in Git Repository",
		Description:   "Some secrets have been found stored in the Git repository. These secrets may be in any historical commit and could be retrieved by anyone with read access to the repository. Test data and false positives can be marked as such.",
		CWEID:         540,
		Score:         report.SeverityThresholdNone, // TODO Decide what criticity a leaked secret should have.
		ImpactDetails: "Anyone with access to the repository could retrieve the leaked secrets and use them the future with malicious intent.",
		Labels:        []string{"issue"},
		Recommendations: []string{
			"Completely remove the secrets from the repository as explained in the references.",
			"Encrypt the secrets using a tool like AWS Secrets Manager or Vault.",
			"Use a \"vulcan-exceptions.yaml\" file as described in the references.",
		},
		References: []string{
			"https://help.github.com/en/articles/removing-sensitive-data-from-a-repository",
		},
		Resources: []report.ResourcesGroup{{
			Name: "Secrets found",
			Header: []string{
				"RuleID",
				"Description",
				"StartLine",
				"StartColumn",
				"EndLine",
				"EndColumn",
			},
		}},
	}
)

type options struct {
	Depth         int      `json:"depth"`
	Branch        string   `json:"branch"`
	GitHistory    bool     `json:"history"`
	ExcludedRules []string `json:"excludedRules"`
	// ExcludedFindings: It would be interesting to allow the users to exclude known FP from the scans, this could be integrated with vulcan-local pretty easily
}

func main() {
	c := check.NewCheckFromHandler(checkName, run)
	c.RunAndServe()
}

func run(ctx context.Context, target, assetType, optJSON string, state checkstate.State) (err error) {
	if target == "" {
		return errors.New("check target missing")
	}

	logger = logger.WithFields(logrus.Fields{
		"target":     target,
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
		logger.Debug("using credentials for GitHub")
	}

	gitCreds := &helpers.GitCreds{}
	if auth != nil {
		gitCreds.User = auth.Username
		gitCreds.Pass = auth.Password
	}
	isReachable, err := helpers.IsReachable(target, assetType, gitCreds)
	if err != nil {
		logger.WithError(err).Warn("can not check asset reachability")
	}
	if !isReachable {
		return checkstate.ErrAssetUnreachable
	}

	repoPath := filepath.Join(os.TempDir(), "repo")
	if err := os.Mkdir(repoPath, 0755); err != nil {
		return err
	}

	logger.WithFields(logrus.Fields{"repo_path": repoPath}).Debug("cloning repo")

	co := git.CloneOptions{
		URL:   target,
		Auth:  auth,
		Depth: opt.Depth,
	}
	if opt.Branch != "" {
		co.ReferenceName = plumbing.ReferenceName(path.Join("refs/heads", opt.Branch))
	}
	_, err = git.PlainClone(repoPath, false, &co)
	if err != nil {
		return err
	}

	// Run gitleaks.
	err = runGitleaks(ctx, logger, repoPath)
	if err != nil {
		return err
	}

	// Read the results file
	byteValue, err := ioutil.ReadFile(reportOutputFile)
	if err != nil {
		logger.Errorf("gitleaks report output file read failed with error: %s\n", err)
		return errors.New("gitleaks report output file read failed")
	}

	var results []Finding
	err = json.Unmarshal(byteValue, &results)
	if err != nil {
		return errors.New("unmarshal gitleaks output failed")
	}

	// Process the secrets found by gitleaks.
	return processVulns(results, opt, repoPath, target, state)
}

func processVulns(results []Finding, opt options, repoPath string, target string, state checkstate.State) error {
	// Return if there are no secrets.
	if len(results) < 1 {
		return nil
	}

	// Group secrets by file.
	resources := map[string][]map[string]string{}
	for _, f := range results {
		if stringInSlice(f.RuleID, &opt.ExcludedRules) {
			continue
		}
		file := strings.TrimPrefix(f.File, repoPath)
		resources[file] = append(resources[file], map[string]string{
			"RuleID":      f.RuleID,
			"Description": f.Description,
			"StartLine":   fmt.Sprint(f.StartLine),
			"StartColumn": fmt.Sprint(f.StartColumn),
			"EndLine":     fmt.Sprint(f.EndLine),
			"EndColumn":   fmt.Sprint(f.EndColumn),
			// "Fingerprint": We could add a Fingerprint here to allow users to except concrete findings.
		})
	}

	// Create a vulnerability for each file.
	for file := range resources {
		v := leakedSecret
		v.AffectedResource = strings.Join([]string{target, file}, "")
		v.Fingerprint = helpers.ComputeFingerprint(resources[file]) // TODO: think a proper way to compute the fingerprint
		v.Resources[0].Rows = resources[file]
		state.AddVulnerabilities(v)
	}

	return nil
}

func stringInSlice(a string, list *[]string) bool {
	for _, b := range *list {
		if b == a {
			return true
		}
	}
	return false
}
