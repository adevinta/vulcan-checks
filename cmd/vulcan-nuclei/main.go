package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/ioutil"
	"os/exec"
	"strings"
	"time"

	report "github.com/adevinta/vulcan-report"

	check "github.com/adevinta/vulcan-check-sdk"
	"github.com/adevinta/vulcan-check-sdk/helpers"
	checkstate "github.com/adevinta/vulcan-check-sdk/state"
	"github.com/avast/retry-go"
)

var (
	checkName          = "vulcan-nuclei"
	logger             = check.NewCheckLog(checkName)
	userAgent          = "x-vulcan-nuclei"
	nucleiCmd          = "./nuclei"
	nucleiTemplatePath = "/root/nuclei-templates/"
)

type void struct{}

type options struct {
	ForceUpdateTemplates  bool     `json:"force_update_templates"`
	Severities            []string `json:"severities"`
	TemplateInclusionList []string `json:"template_inclusion_list"`
	TemplateExclusionList []string `json:"template_exclusion_list"`
}

// Vulnerability defines nuclei vulnerability report struct.
type Vulnerability struct {
	Name        string `json:"name"`
	Author      string `json:"author"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	Matched     string `json:"matched"`
	Template    string `json:"template"`
	Type        string `json:"type"`
	Host        string `json:"host"`
}

type finding struct {
	name     string
	severity string
	template string
	match    string
}

func main() {
	c := check.NewCheckFromHandler(checkName, run)
	c.RunAndServe()
}

func runNucleiCmd(args []string) ([]byte, error) {
	var err error
	var cmdOutput []byte
	err = retry.Do(
		func() error {
			cmd := exec.Command(nucleiCmd, args...)
			cmdOutput, err = cmd.Output()
			if err != nil {
				logger.Errorf("exec.Command() with args [%s] failed with %s\nCommand output: %s\n", args, err, string(cmdOutput))
				return errors.New("nuclei command execution failed")
			}
			logger.Infof("nuclei command with args [%s] execution completed successfully", args)
			return nil
		},
		retry.Attempts(3),
		retry.DelayType(retry.RandomDelay),
		retry.MaxJitter(5*time.Second),
	)
	if err != nil {
		return []byte{}, err
	}
	return cmdOutput, nil
}

func run(ctx context.Context, target, assetType, optJSON string, state checkstate.State) error {
	// TODO: If options are "malformed" perhaps we should not return error
	// but only log and error and return.
	var opt options
	if optJSON != "" {
		if err := json.Unmarshal([]byte(optJSON), &opt); err != nil {
			return err
		}
	}

	isReachable := helpers.IsWebAddrsReachable(target)
	if !isReachable {
		return checkstate.ErrAssetUnreachable
	}

	if opt.ForceUpdateTemplates {
		_, err := runNucleiCmd([]string{"-update-templates"})
		if err != nil {
			return errors.New("nuclei update-templates command execution failed")
		}
	}

	availableTemplates := make(map[string]void)
	logger.Debugf("Templates path: %s", nucleiTemplatePath)
	tf, err := ioutil.ReadDir(nucleiTemplatePath)
	if err != nil {
		return errors.New("unable to read nuclei templates folder")
	}

	for _, f := range tf {
		if f.IsDir() {
			availableTemplates[f.Name()] = void{}
		}
	}
	logger.Infof("Available templates: %+v", availableTemplates)

	selectedTemplates := make(map[string]void)
	logger.Infof("Included templates: %+v", opt.TemplateInclusionList)
	if len(opt.TemplateInclusionList) > 0 {
		for _, v := range opt.TemplateInclusionList {
			if _, ok := availableTemplates[v]; ok {
				selectedTemplates[v] = void{}
			}
		}
	} else {
		for k := range availableTemplates {
			selectedTemplates[k] = void{}
		}
	}

	// Remove exclued templates from selectedTemplates.
	logger.Infof("Exclued templates: %+v", opt.TemplateExclusionList)
	// Explicitly remove ".github" in case it exists.
	opt.TemplateExclusionList = append(opt.TemplateExclusionList, ".github")
	for _, v := range opt.TemplateExclusionList {
		if _, ok := selectedTemplates[v]; ok {
			delete(selectedTemplates, v)
		}
	}

	logger.Infof("Selected templates: %+v", selectedTemplates)
	// No templates selected. Return.
	if len(selectedTemplates) < 1 {
		return nil
	}

	// Build arguments.
	nucleiArgs := []string{
		"-target", target,
		"-c", "20",
		"-json",
		"-silent",
		"-H", userAgent,
	}

	// Include only selected severities.
	selectedSeverities := strings.Join(opt.Severities, ",")
	if len(opt.Severities) > 0 {
		logger.Infof("Selected severities: %s", selectedSeverities)
		severities := []string{"-severity", selectedSeverities}
		nucleiArgs = append(nucleiArgs, severities...)
	}

	logger.Debugf("nuclei command args: [%s]", nucleiArgs)
	var vulns []Vulnerability
	for t := range selectedTemplates {
		nucleiArgsWithTemplate := append(nucleiArgs, "-t", t)
		output, err := runNucleiCmd(nucleiArgsWithTemplate)
		if err != nil {
			logger.Errorf("nuclei execution failed with template [%s]: %s", t, err)
			continue
		}
		if len(output) == 0 {
			logger.Infof("no vulnerabilities found with template [%s]", t)
			continue
		}
		scanner := bufio.NewScanner(bytes.NewReader(output))
		for scanner.Scan() {
			var v Vulnerability
			err := json.Unmarshal(scanner.Bytes(), &v)
			if err != nil {
				logger.Errorf("unable to unmarshal vulnerability [%s]: %s", scanner.Text(), err)
				continue
			}
			vulns = append(vulns, v)
		}
	}
	// No vulnerabilities found. Return.
	if len(vulns) < 1 {
		logger.Info("no vulnerabilities found")
		return nil
	}

	logger.Infof("nuclei found [%d] vulnerabilities", len(vulns))
	for _, v := range vulns {
		score := getScore(v.Severity)
		var vuln = report.Vulnerability{
			Summary:     v.Name,
			Description: v.Description,
			Score:       score,
		}
		row := map[string]string{
			"Severity": v.Severity,
			"Type":     v.Type,
			"Template": v.Template,
			"Matched":  v.Matched,
		}
		finding := report.ResourcesGroup{
			Name: "Finding",
			Header: []string{
				"Severity",
				"Type",
				"Template",
				"Matched",
			},
		}
		finding.Rows = append(finding.Rows, row)
		vuln.Resources = append(vuln.Resources, finding)
		state.AddVulnerabilities(vuln)
	}

	return nil
}

func getScore(severity string) float32 {
	if severity == "critical" {
		return report.SeverityThresholdCritical
	}
	if severity == "high" {
		return report.SeverityThresholdHigh
	}
	if severity == "medium" {
		return report.SeverityThresholdMedium
	}
	if severity == "low" {
		return report.SeverityThresholdLow
	}
	return report.SeverityThresholdNone
}
