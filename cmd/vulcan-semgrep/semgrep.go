package main

import (
	"context"
	"fmt"

	"github.com/adevinta/vulcan-check-sdk/helpers/command"
	"github.com/sirupsen/logrus"
)

const (
	Cmd = `semgrep`
)

var params = []string{"--json", "--timeout", "0", "-c"}

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
		Metadata struct {
			Owasp         string   `json:"owasp"`
			Cwe           string   `json:"cwe"`
			SourceRuleURL string   `json:"source-rule-url"`
			References    []string `json:"references"`
		} `json:"metadata"`
		Severity string `json:"severity"`
		Fix      string `json:"fix"`
		Lines    string `json:"lines"`
	} `json:"extra,omitempty"`
}

func runSemgrep(ctx context.Context, logger *logrus.Entry, ruleset, dir string) (*SemgrepOutput, error) {
	params = append(params, ruleset, dir)

	var report SemgrepOutput
	exitCode, err := command.ExecuteAndParseJSON(ctx, logger, &report, Cmd, params...)
	if err != nil {
		return nil, err
	}

	/*
		Semgrep exit codes:
			0: Semgrep ran successfully and found no errors
			1: Semgrep ran successfully and found issues in your code
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

	logger.WithFields(logrus.Fields{"exit_code": exitCode, "report": report}).Debug("semgrep command finished")

	switch exitCode {
	// Don't fail the check for unsupported languages.
	case 2, 3, 4, 5, 6, 7, 9, 10, 11:
		err := fmt.Errorf("semgrep scan failed with exit code %d", exitCode)

		logger.WithError(err).WithFields(logrus.Fields{"errors": report.Errors}).Error("")

		return nil, err
	case 8:
		return nil, nil
	}

	return &report, nil
}
