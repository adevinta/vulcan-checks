/*
Copyright 2019 Adevinta
*/

package main

import (
	"context"

	"github.com/adevinta/vulcan-check-sdk/helpers/command"
	"github.com/sirupsen/logrus"
)

const Cmd = `gitleaks`

var params = []string{"detect", "-f", "json", "--no-git", "--no-banner", "--no-color", "-r", "-"}

type Finding struct {
	Description string `json:"Description"`
	StartLine   int    `json:"StartLine"`
	EndLine     int    `json:"EndLine"`
	StartColumn int    `json:"StartColumn"`
	EndColumn   int    `json:"EndColumn"`

	Match string `json:"Match"`

	// Secret contains the full content of what is matched in
	// the tree-sitter query.
	Secret string `json:"Secret"`

	// File is the name of the file containing the finding
	File string `json:"File"`

	Commit string `json:"Commit"`

	// Entropy is the shannon entropy of Value
	Entropy float32 `json:"Entropy"`

	Author  string   `json:"Author"`
	Email   string   `json:"Email"`
	Date    string   `json:"Date"`
	Message string   `json:"Message"`
	Tags    []string `json:"Tags"`

	// Rule is the name of the rule that was matched
	RuleID string `json:"RuleID"`
}

func runGitleaks(ctx context.Context, logger *logrus.Entry, dir string) ([]Finding, error) {
	params = append(params, "-s", dir)

	var findings []Finding
	exitCode, err := command.ExecuteAndParseJSON(ctx, logger, &findings, Cmd, params...)
	if err != nil {
		return nil, err
	}

	logger.WithFields(logrus.Fields{"exit_code": exitCode}).Debug("gitleaks command finished")
	return findings, nil
}
