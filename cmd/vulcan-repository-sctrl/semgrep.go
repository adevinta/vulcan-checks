package main

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/adevinta/vulcan-check-sdk/helpers/command"
	"github.com/sirupsen/logrus"
)

const Cmd = `semgrep`

const DefaultRuleConfigPath = `/custom-rules/repository-with-security-control.yaml`

// NOTE: keep this const block separated to not mess with the iota generated
// values.
const (
	/*
		Semgrep exit codes from https://semgrep.dev/docs/cli-usage/#exit-codes:
			0: Semgrep ran successfully and found no errors (or did find errors, but the --error flag is not set)
			1: Semgrep ran successfully and found issues in your code (and the --error flag is set)
			2: Semgrep failed
			3: Semgrep failed to parse a file in the specified language
			4: Semgrep encountered an invalid pattern
			5: Semgrep config is not valid yaml
			6: Rule with pattern-where-python found but --dangerously-allow-arbitrary-code-execution-from-rules was not set. See --dangerously-allow-arbitrary-code-execution-from-rules.
			7: All rules in config are invalid. If semgrep is run with --strict then this exit code is returned when any rule in the configs are invalid.
			8: Semgrep does not understand specified language
			9: Semgrep exceeded match timeout. See --timeout
			10: Semgrep exceeded max memory while matching. See --max-memory.
			11: Semgrep encountered a lexical error when running rule on a file.
	*/
	SemgrepStatusOK = iota // This should be always 0.
	SemgrepStatusOKWithIssues
	SemgrepStatusFailed
	SemgrepStatusFailedParsingFile
	SemgrepStatusFailedInvalidPattern
	SemgrepStatusFailedConfig
	SemgrepStatusFailedUnsafe
	SemgrepStatusFailedInvalidRules
	SemgrepStatusFailedUnknownLanguage
	SemgrepStatusFailedTimeout
	SemgrepStatusFailedMaxMemory
	SemgrepStatusFailedLexical
)

var AlwaysExcluded = []string{"*swagger*.js"}

// SemgrepOutput and Result represent the output information from the semgrep
// command.  Non-used fields have been intentionally ommitted.
type SemgrepOutput struct {
	Results []Result      `json:"results"`
	Errors  []interface{} `json:"errors"`
}
type Result struct {
	CheckID string `json:"check_id"`
	Path    string `json:"path"`
	Start   struct {
		Line int `json:"line"`
	} `json:"start"`
	Extra struct {
		Message  string `json:"message"`
		Metavars struct {
			AbstractContent string `json:"abstract_content"`
		} `json:"metavars"`
	} `json:"extra,omitempty"`
}

func semgrepFindings(logger *logrus.Entry, r SemgrepOutput, target, repo, branch string) []map[string]string {
	findingRows := []map[string]string{}
	if len(r.Results) < 1 {
		logger.Info("no security controls found by semgrep")
		return findingRows
	}

	logger.WithFields(logrus.Fields{"num_results": len(r.Results)}).Info("security controls found. Processing results")

	for _, result := range r.Results {
		filepath := strings.TrimPrefix(result.Path, fmt.Sprintf("%s/", repo))
		path := fmt.Sprintf("%s:%d", filepath, result.Start.Line)
		link := strings.TrimSuffix(target, ".git") + "/blob/" + branch + "/" + filepath + "#L" + fmt.Sprint(result.Start.Line)
		row := map[string]string{
			"Control": result.Extra.Message,
			"Path":    path,
			"Link":    fmt.Sprintf("(Link)[%s]", link),
		}
		findingRows = append(findingRows, row)
	}

	return findingRows
}

func runSemgrep(ctx context.Context, logger *logrus.Entry, timeout int, ruleConfigPath string, dir string) (SemgrepOutput, error) {
	if ruleConfigPath == "" {
		ruleConfigPath = DefaultRuleConfigPath
	}
	var params = []string{"--json", "--config", ruleConfigPath}
	params = append(params, "--timeout", strconv.Itoa(timeout))
	params = append(params, dir)

	var report SemgrepOutput
	exitCode, err := command.ExecuteAndParseJSON(ctx, logger, &report, Cmd, params...)
	if err != nil {
		return report, err
	}

	logger.WithFields(logrus.Fields{"exit_code": exitCode, "report": report}).Debug("semgrep command finished")

	switch exitCode {
	case SemgrepStatusOK, SemgrepStatusOKWithIssues:
		return report, nil
	// Don't fail the check for unsupported languages.
	case SemgrepStatusFailedUnknownLanguage:
		return report, nil
	default:
		err := fmt.Errorf("semgrep scan failed with exit code %d", exitCode)
		logger.WithError(err).WithFields(logrus.Fields{"errors": report.Errors}).Error("")
		return report, err
	}
}
