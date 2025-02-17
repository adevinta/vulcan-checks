/*
Copyright 2019 Adevinta
*/

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"

	check "github.com/adevinta/vulcan-check-sdk"
	"github.com/adevinta/vulcan-check-sdk/helpers"
	checkstate "github.com/adevinta/vulcan-check-sdk/state"
	report "github.com/adevinta/vulcan-report"
	"github.com/sirupsen/logrus"
)

const (
	checkName    = "vulcan-gitleaks"
	DefaultDepth = 1
)

var (
	localTargets = []string{"localhost", "host.docker.internal", "172.17.0.1", "172.18.0.1"}
	leakedSecret = report.Vulnerability{
		Summary:       "Secret Leaked in Git Repository",
		Description:   "A secret has been found stored in the Git repository. This secret may be in any historical commit and could be retrieved by anyone with read access to the repository. Test data and false positives can be marked as such.",
		CWEID:         540,
		Score:         8.9,
		ImpactDetails: "Anyone with access to the repository could retrieve the leaked secret and use it in the future with malicious intent.",
		Labels:        []string{"issue"},
		Recommendations: []string{
			"Completely remove the secrets from the repository as explained in the references.",
			"Encrypt the secrets using a tool like AWS Secrets Manager or Vault.",
		},
		References: []string{
			"https://help.github.com/en/articles/removing-sensitive-data-from-a-repository",
		},
	}
	remoteDetails = "This secret was found by the gitleaks rule '%s', with ID '%s'. If this doesn't correspond to a secret, it can be excluded from future scans marking it as false positive."
	localDetails  = "This secret was found by the gitleaks rule '%s', with ID '%s'. If this doesn't correspond to a secret, it can be excluded by adding the following line to vulcan.yaml file for vulcan-local executions:\n \t- affectedResource: %s"
	resource      = report.ResourcesGroup{
		Name: "Secrets found",
		Header: []string{
			"RuleID",
			"Description",
			"StartLine",
			"StartColumn",
			"EndLine",
			"EndColumn",
			"Link",
		},
	}
)

type options struct {
	Depth         int      `json:"depth"`
	Branch        string   `json:"branch"`
	GitHistory    bool     `json:"history"`
	ExcludedRules []string `json:"excludedRules"`
}

func main() {
	c := check.NewCheckFromHandler(checkName, run)
	c.RunAndServe()
}

func run(ctx context.Context, target, assetType, optJSON string, state checkstate.State) (err error) {
	logger := check.NewCheckLogFromContext(ctx, checkName)

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

	repoPath, branch, err := helpers.CloneGitRepositoryContext(ctx, target, opt.Branch, opt.Depth)
	if err != nil {
		return err
	}
	defer os.RemoveAll(repoPath)

	// Run gitleaks.
	results, err := runGitleaks(ctx, logger, repoPath)
	if err != nil {
		return err
	}

	// Process the secrets found by gitleaks.
	return processVulns(results, opt, repoPath, branch, target, state)
}

func processVulns(results []Finding, opt options, repoPath string, branch string, target string, state checkstate.State) error {
	// Return if there are no findings.
	if len(results) < 1 {
		return nil
	}

	for _, f := range results {
		if stringInSlice(f.RuleID, &opt.ExcludedRules) {
			continue
		}
		file := strings.TrimPrefix(f.File, repoPath)
		v := leakedSecret
		h := sha256.New()
		s := hex.EncodeToString(h.Sum([]byte(f.Secret)))[1:48]
		v.AffectedResource = string(s)
		affectedResourceString := computeAffectedResource(target, branch, file, f.StartLine)
		v.AffectedResourceString = affectedResourceString
		v.Fingerprint = helpers.ComputeFingerprint()
		v.Details = setDetails(target, f, s)
		resource.Rows = []map[string]string{
			{
				"RuleID":      f.RuleID,
				"Description": f.Description,
				"StartLine":   fmt.Sprint(f.StartLine),
				"StartColumn": fmt.Sprint(f.StartColumn),
				"EndLine":     fmt.Sprint(f.EndLine),
				"EndColumn":   fmt.Sprint(f.EndColumn),
				"Link":        fmt.Sprintf("[Link](%s)", affectedResourceString),
			},
		}
		v.Resources = []report.ResourcesGroup{resource}
		state.AddVulnerabilities(v)
	}
	return nil
}

func computeAffectedResource(target, branch string, file string, l int) string {
	u, _ := url.Parse(target)
	if stringInSlice(u.Hostname(), &localTargets) {
		return strings.Join([]string{strings.TrimPrefix(file, "/"), "#", fmt.Sprint(l)}, "")
	}

	return helpers.GenerateGithubURL(target, branch, file, l)
}

func setDetails(target string, f Finding, s string) string {
	u, _ := url.Parse(target)
	if stringInSlice(u.Hostname(), &localTargets) {
		return fmt.Sprintf(localDetails, f.Description, f.RuleID, string(s))
	}
	return fmt.Sprintf(remoteDetails, f.Description, f.RuleID)
}

func stringInSlice(a string, list *[]string) bool {
	for _, b := range *list {
		if b == a {
			return true
		}
	}
	return false
}
