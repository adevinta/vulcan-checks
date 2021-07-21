package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/src-d/go-git.v4"
	http "gopkg.in/src-d/go-git.v4/plumbing/transport/http"

	check "github.com/adevinta/vulcan-check-sdk"
	"github.com/adevinta/vulcan-check-sdk/helpers"
	checkstate "github.com/adevinta/vulcan-check-sdk/state"
	report "github.com/adevinta/vulcan-report"
	"github.com/sirupsen/logrus"
)

const (
	DefaultDepth   = 1
	DefaultRuleset = `p/r2c-security-audit`
)

var (
	checkName = "vulcan-semgrep"
	logger    = check.NewCheckLog(checkName)

	severityMap = map[string]report.SeverityRank{
		"INFO":    report.SeverityNone,
		"WARNING": report.SeverityLow,
		"ERROR":   report.SeverityMedium,
	}
)

type options struct {
	Depth   int    `json:"string"`
	Ruleset string `json:"ruleset"`
}

func main() {
	run := func(ctx context.Context, target, assetType, optJSON string, state checkstate.State) error {
		if target == "" {
			return errors.New("check target missing")
		}

		logger = logger.WithFields(logrus.Fields{
			"target":     target,
			"asset_type": assetType,
		})

		opt := options{
			Depth:   DefaultDepth,
			Ruleset: DefaultRuleset,
		}
		if optJSON != "" {
			if err := json.Unmarshal([]byte(optJSON), &opt); err != nil {
				return err
			}
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

		repoPath := filepath.Join("/tmp", filepath.Base(targetURL.Path))
		if err := os.Mkdir(repoPath, 0755); err != nil {
			return err
		}

		logger.WithFields(logrus.Fields{"repo_path": repoPath}).Debug("cloning repo")

		_, err = git.PlainClone(repoPath, false, &git.CloneOptions{
			URL:   target,
			Auth:  auth,
			Depth: opt.Depth,
		})
		if err != nil {
			return err
		}

		r, err := runSemgrep(ctx, logger, opt.Ruleset, repoPath)
		if err != nil {
			return err
		}

		addVulnsToState(state, r, repoPath, target)

		return nil
	}

	c := check.NewCheckFromHandler(checkName, run)
	c.RunAndServe()
}

func addVulnsToState(state checkstate.State, r *SemgrepOutput, repoPath, target string) {
	if r == nil || len(r.Results) < 1 {
		return
	}

	logger.WithFields(logrus.Fields{"num_results": len(r.Results)}).Info("processing results")

	vulns := make(map[string]report.Vulnerability)
	for _, result := range r.Results {
		filepath := strings.TrimPrefix(result.Path, fmt.Sprintf("%s/", repoPath))
		path := fmt.Sprintf("%s:%d", filepath, result.Start.Line)

		v := vuln(result, filepath, vulns)

		row := map[string]string{
			"Path":  path,
			"Match": result.Extra.Lines,
			"Fix":   result.Extra.Fix,
			// Message will be removed afterwards if it has the same value in
			// all the rows.
			"Message": result.Extra.Message,
		}

		// In almost all cases the message is the same for all the results of
		// the same rule, but there are few cases where message differs. In
		// those few cases we will be adding the alternative messages in the
		// resources table.
		if result.Extra.Message != v.Description && len(v.Resources[0].Header) == 3 {
			logger.WithFields(logrus.Fields{"vulnerability": v.Summary}).Info("vulnerability has alternative messages")

			v.Resources[0].Header = append(v.Resources[0].Header, "Message")
			v.Description = ""
		}

		v.Resources[0].Rows = append(v.Resources[0].Rows, row)

		key := fmt.Sprintf("%s - %s", v.Summary, filepath)
		vulns[key] = v
	}

	for _, v := range vulns {
		// Sort rows by alphabetical order of the path.
		sort.Slice(v.Resources[0].Rows, func(i, j int) bool {
			return v.Resources[0].Rows[i]["Path"] < v.Resources[0].Rows[j]["Path"]
		})

		// Compute vulnerability fingerprint based on Match.
		var matches []string
		for _, row := range v.Resources[0].Rows {
			matches = append(matches, row["Match"])

			// Delete Message from the row to avoid storing unnecesary messages
			// when are all the same.
			if len(v.Resources[0].Header) == 3 {
				delete(row, "Message")
			}
		}

		v.ID = computeVulnerabilityID(target, v.AffectedResource, matches)

		state.AddVulnerabilities(v)
	}
}

func vuln(result Result, filepath string, vulns map[string]report.Vulnerability) report.Vulnerability {
	logger.WithFields(logrus.Fields{"check_id": result.CheckID, "cwe": result.Extra.Metadata.Cwe}).Debug("processing result")

	// Check ID example:
	//	python.lang.security.unquoted-csv-writer.unquoted-csv-writer
	checkIDParts := strings.Split(result.CheckID, ".")

	issue := checkIDParts[len(checkIDParts)-1] // Example: unquoted-csv-writer
	issue = strings.ReplaceAll(issue, "-", " ")
	issue = strings.ReplaceAll(issue, "_", " ") // Example: unquoted csv writer

	summary := issue

	// CWE example:
	//	CWE-1236: Improper Neutralization of Formula Elements in a CSV File
	var cweID int
	if result.Extra.Metadata.Cwe != "" {
		aux := strings.TrimPrefix(result.Extra.Metadata.Cwe, "CWE-")
		cweParts := strings.Split(aux, ":")
		// Example:
		//	Improper Neutralization of Formula Elements in a CSV File
		cweText := strings.TrimSpace(cweParts[1])

		// Example:
		//	Improper Neutralization of Formula Elements in a CSV File - Unquoted Csv Writer
		summary = fmt.Sprintf("%s - %s", cweText, summary)

		cweID, _ = strconv.Atoi(cweParts[0])
	}

	summary = strings.Title(summary)

	key := fmt.Sprintf("%s - %s", summary, filepath)
	v, ok := vulns[key]
	if ok {
		return v
	}

	v.Summary = summary
	v.Description = result.Extra.Message
	v.Score = report.ScoreSeverity(severityMap[result.Extra.Severity])
	v.Details = fmt.Sprintf("Check ID: %s\n", result.CheckID)
	v.References = append(v.References, "https://semgrep.dev/")
	v.References = append(v.References, result.Extra.Metadata.References...)
	v.CWEID = uint32(cweID)
	v.AffectedResource = filepath
	v.Labels = []string{"potential_issue"}
	v.Resources = []report.ResourcesGroup{
		report.ResourcesGroup{
			Name: "Found in",
			Header: []string{
				"Path",
				"Match",
				"Fix",
			},
		},
	}

	return v
}

func computeVulnerabilityID(target, affectedResource string, elems ...interface{}) string {
	h := sha256.New()

	fmt.Fprintf(h, "%s - %s", target, affectedResource)

	for _, e := range elems {
		fmt.Fprintf(h, " - %v", e)
	}

	return fmt.Sprintf("%x", h.Sum(nil))
}
