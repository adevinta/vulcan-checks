package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"

	check "github.com/adevinta/vulcan-check-sdk"
	"github.com/adevinta/vulcan-check-sdk/helpers"
	checkstate "github.com/adevinta/vulcan-check-sdk/state"
	report "github.com/adevinta/vulcan-report"
	"github.com/sirupsen/logrus"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

const (
	DefaultDepth = 1
	// DefaultRuleset has been chosen for being one of the most popular
	// rulesets semgrep has. There are less noisy alternatives like the
	// 'r2c-ci' that we might use instead.
	// https://semgrep.dev/explore
	// CWERegexStr defines a regex matching a CWE definition from Semgrep
	// rules.
	// Example:
	//	CWE-1236: Improper Neutralization of Formula Elements in a CSV File
	CWERegexStr    = `CWE-(\d+)\s*:\s*([[:print:]]+)`
	MaxMatchLenght = 1000
	checkName      = "vulcan-semgrep"
)

var (
	DefaultRulesets = []string{"p/r2c-security-audit"}
	severityMap     = map[string]report.SeverityRank{
		"INFO":    report.SeverityNone,
		"WARNING": report.SeverityLow,
		"ERROR":   report.SeverityMedium,
	}

	CWERegex = regexp.MustCompile(CWERegexStr)
	caser    = cases.Title(language.English)
)

type options struct {
	Depth       int         `json:"depth"`
	Branch      string      `json:"branch"`
	Ruleset     interface{} `json:"ruleset"`
	Timeout     int         `json:"timeout"`
	Exclude     []string    `json:"exclude"`
	ExcludeRule []string    `json:"exclude_rule"`
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
		// Ensure not an empty ruleset is provided
		var RulesetArray []string
		switch opt.Ruleset.(type) {
		case string:
			RulesetArray = []string{fmt.Sprintf("%v", opt.Ruleset)}
		case []interface{}:
			if len(opt.Ruleset.([]interface{})) == 0 {
				RulesetArray = DefaultRulesets
			} else {
				for _, v := range opt.Ruleset.([]interface{}) {
					RulesetArray = append(RulesetArray, v.(string))
				}
			}
		case nil:
			RulesetArray = DefaultRulesets
		}
		if opt.Depth == 0 {
			opt.Depth = DefaultDepth
		}

		logger.WithFields(logrus.Fields{"options": opt}).Debug("using options")

		repoPath, _, err := helpers.CloneGitRepositoryContext(ctx, target, opt.Branch, opt.Depth)
		if err != nil {
			return err
		}
		defer os.RemoveAll(repoPath)

		r, err := runSemgrep(ctx, logger, opt.Timeout, opt.Exclude, opt.ExcludeRule, RulesetArray, repoPath)
		if err != nil {
			return err
		}

		addVulnsToState(logger, state, r, repoPath)

		return nil
	}

	c := check.NewCheckFromHandler(checkName, run)
	c.RunAndServe()
}

func addVulnsToState(logger *logrus.Entry, state checkstate.State, r *SemgrepOutput, repoPath string) {
	if r == nil || len(r.Results) < 1 {
		return
	}

	logger.WithFields(logrus.Fields{"num_results": len(r.Results)}).Info("processing results")

	vulns := make(map[string]report.Vulnerability)
	for _, result := range r.Results {
		filepath := strings.TrimPrefix(result.Path, fmt.Sprintf("%s/", repoPath))
		path := fmt.Sprintf("%s:%d", filepath, result.Start.Line)

		v := vuln(logger, result, filepath, vulns)
		match := result.Extra.Lines
		if len(result.Extra.Lines) > MaxMatchLenght {
			match = result.Extra.Lines[:MaxMatchLenght] + "..."
		}
		row := map[string]string{
			"Path":  path,
			"Match": match,
			"Fix":   result.Extra.Fix,
			// Message will be removed afterwards if it has the same value in
			// all the rows.
			"Message": result.Extra.Message,
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

		// Compute vulnerability fingerprint based on Match, and check if all
		// Messages are the same.
		// In almost all cases the Message is the same for all the results of
		// the same rule, but there are few cases where message differs. In
		// those few cases we will be adding the alternative messages in the
		// resources table. In case is the Message is the same for all entries,
		// we will add the Message just to the Details and delete it from the
		// rows to avoid storing unnecesary messages when are all the same.
		// NOTE: We are not adding the Message to the Description as there
		// might be corner cases where we may end having duplicated issues in
		// the Vulnerability DB.
		var matches []string
		same := true
		msg := ""
		for i, row := range v.Resources[0].Rows {
			matches = append(matches, row["Match"])

			if i == 0 {
				msg = row["Message"]
			}
			if same && (row["Message"] != msg) {
				same = false
			}
		}
		if same {
			if msg != "" {
				v.Details = fmt.Sprintf("%s\n\n%s", msg, v.Details)
			}
			for _, row := range v.Resources[0].Rows {
				delete(row, "Message")
			}
		} else {
			v.Resources[0].Header = append(v.Resources[0].Header, "Message")
			logger.WithFields(logrus.Fields{"vulnerability": v.Summary}).Info("vulnerability has alternative messages")
		}

		v.Fingerprint = helpers.ComputeFingerprint(matches)

		state.AddVulnerabilities(v)
	}
}

func vuln(logger *logrus.Entry, result Result, filepath string, vulns map[string]report.Vulnerability) report.Vulnerability {
	logger.WithFields(logrus.Fields{"check_id": result.CheckID, "cwe": result.Extra.Metadata.Cwe}).Debug("processing result")

	// Check ID example:
	//	python.lang.security.unquoted-csv-writer.unquoted-csv-writer
	checkIDParts := strings.Split(result.CheckID, ".")

	issue := checkIDParts[len(checkIDParts)-1] // Example: unquoted-csv-writer
	issue = strings.ReplaceAll(issue, "-", " ")
	issue = strings.ReplaceAll(issue, "_", " ") // Example: unquoted csv writer

	summary := issue

	var cweID int

	// Most of the times Cwe is an []string, in that case use the first one.
	firstCwe := ""
	if slice, ok := result.Extra.Metadata.Cwe.([]interface{}); ok {
		if len(slice) > 0 {
			firstCwe = fmt.Sprintf("%v", slice[0])
		}
	} else if s, ok := result.Extra.Metadata.Cwe.(string); ok {
		firstCwe = s
	}
	if matches := CWERegex.FindStringSubmatch(firstCwe); len(matches) == 3 {
		cweText := strings.TrimSpace(matches[2])

		// Example:
		//	Improper Neutralization of Formula Elements in a CSV File - Unquoted Csv Writer
		summary = fmt.Sprintf("%s - %s", cweText, summary)

		cweID, _ = strconv.Atoi(matches[1])
	}

	summary = caser.String(summary)

	key := fmt.Sprintf("%s - %s", summary, filepath)
	v, ok := vulns[key]
	if ok {
		return v
	}

	v.Summary = summary
	v.Description = ""
	v.Score = report.ScoreSeverity(severityMap[result.Extra.Severity])
	v.Details = fmt.Sprintf("Check ID: %s\n", result.CheckID)
	v.References = append(v.References, "https://semgrep.dev/")
	v.References = append(v.References, result.Extra.Metadata.References...)
	v.CWEID = uint32(cweID)
	v.AffectedResource = filepath
	v.Labels = []string{"potential", "code", "semgrep"}
	v.Resources = []report.ResourcesGroup{
		{
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
