package main

import (
	"context"
	"fmt"

	"github.com/adevinta/vulcan-check-sdk/helpers/command"
	"github.com/sirupsen/logrus"
)

const Cmd = `njsscan`

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

var params = []string{"--json"}

// SemgrepOutput and Result represent the output information from the semgrep
// command.  Non-used fields have been intentionally ommitted.

type NjsscanOutput struct {
	NjsscanVersion string        `json:"njsscan_version"`
	Errors         []interface{} `json:"errors"`
	NodeJS         interface{}   `json:"nodejs"`
	Templates      interface{}   `json:"templates"`
}

// type Result struct {
// 	CheckID string `json:"check_id"`
// 	Path    string `json:"path"`
// 	Start   struct {
// 		Line int `json:"line"`
// 	} `json:"start"`
// 	Extra struct {
// 		Message  string `json:"message"`
// 		Metadata struct {
// 			// The field Owasp can be a string or a []string
// 			// Owasp         string   `json:"owasp"`
// 			Cwe           interface{} `json:"cwe"` // string or []string
// 			SourceRuleURL string      `json:"source-rule-url"`
// 			References    []string    `json:"references"`
// 		} `json:"metadata"`
// 		Severity string `json:"severity"`
// 		Fix      string `json:"fix"`
// 		Lines    string `json:"lines"`
// 	} `json:"extra,omitempty"`
// }

func runSemgrep(ctx context.Context, logger *logrus.Entry, dir string) (*NjsscanOutput, error) {
	params = append(params, dir)

	var report NjsscanOutput
	exitCode, err := command.ExecuteAndParseJSON(ctx, logger, &report, Cmd, params...)
	if err != nil {
		return nil, err
	}
	fmt.Println(report)
	logger.WithFields(logrus.Fields{"exit_code": exitCode, "report": report}).Debug("semgrep command finished")

	switch exitCode {
	case SemgrepStatusOK, SemgrepStatusOKWithIssues:
		return &report, nil
	// Don't fail the check for unsupported languages.
	case SemgrepStatusFailedUnknownLanguage:
		return nil, nil
	default:
		err := fmt.Errorf("semgrep scan failed with exit code %d", exitCode)
		logger.WithError(err).WithFields(logrus.Fields{"errors": report.Errors}).Error("")
		return nil, err
	}
}
