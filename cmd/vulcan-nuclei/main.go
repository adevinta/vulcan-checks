/*
Copyright 2022 Adevinta
*/

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	report "github.com/adevinta/vulcan-report"

	check "github.com/adevinta/vulcan-check-sdk"
	"github.com/adevinta/vulcan-check-sdk/helpers"
	checkstate "github.com/adevinta/vulcan-check-sdk/state"
	"github.com/avast/retry-go"
)

var (
	checkName              = "vulcan-nuclei"
	logger                 = check.NewCheckLog(checkName)
	userAgent              = "x-vulcan-nuclei"
	nucleiCmd              = "nuclei"
	nucleiTemplatePath     = "/root/nuclei-templates/"
	nucleiTemplateListJSON = "TEMPLATES-STATS.json"

	defaultTagExclusionList = []string{
		"intrusive",
		"fuzz",
		"dos",
	}

	defaultTemplateExclusionList = []string{
		"fuzzing",
		"helpers",
		"workflows",
	}
)

type void struct{}

type options struct {
	UpdateTemplates       bool     `json:"update_templates"`
	Severities            []string `json:"severities"`
	TemplateInclusionList []string `json:"template_inclusion_list"`
	TemplateExclusionList []string `json:"template_exclusion_list"`
	TagInclusionList      []string `json:"tag_inclusion_list"`
	TagExclusionList      []string `json:"tag_exclusion_list"`
}

// TemplateList defines nuclei templates available.
type TemplateList struct {
	Directory []struct {
		Name  string `json:"name"`
		Count int    `json:"count"`
	} `json:"directory"`
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
	var opt options
	if optJSON != "" {
		if err := json.Unmarshal([]byte(optJSON), &opt); err != nil {
			return err
		}
	}

	// Update templates at runtime only if specified.
	if opt.UpdateTemplates {
		logger.Infof("updating templates to their latest version")
		_, err := runNucleiCmd([]string{"-ut"})
		if err != nil {
			logger.Warnf("nuclei failed updating templates: %v", err)
		}
	}

	// Create list of excluded templates.
	if len(opt.TemplateExclusionList) == 0 {
		logger.Info("no template exclusion list provided, applying default template exclusion list")
		opt.TemplateExclusionList = defaultTemplateExclusionList
	}

	// Create list of excluded tags.
	if len(opt.TagExclusionList) == 0 {
		logger.Info("no tag exclusion list provided, applying default tag exclusion list")
		opt.TagExclusionList = defaultTagExclusionList
	}

	isReachable, err := helpers.IsReachable(target, assetType, nil)
	if err != nil {
		logger.Warnf("can not check asset reachability: %v", err)
	}
	if !isReachable {
		return checkstate.ErrAssetUnreachable
	}

	logger.Infof("included templates: %+v", opt.TemplateInclusionList)
	logger.Infof("excluded templates: %+v", opt.TemplateExclusionList)
	logger.Infof("included tags: %+v", opt.TagInclusionList)
	logger.Infof("excluded tags: %+v", opt.TagExclusionList)

	nucleiArgs := buildNucleiScanCmdArgs(target, opt)

	nucleiFindings, err := runNuclei(nucleiArgs)
	if err != nil {
		return err
	}
	// No vulnerabilities found. Return.
	if len(nucleiFindings) < 1 {
		logger.Info("no vulnerabilities found")
		return nil
	}
	logger.Infof("nuclei found [%d] vulnerabilities", len(nucleiFindings))

	vulnerabilities := processNucleiFindings(target, nucleiFindings)
	for _, v := range vulnerabilities {
		state.AddVulnerabilities(*v)
	}

	return nil
}

func processNucleiFindings(target string, nucleiFindings []ResultEvent) []*report.Vulnerability {
	vulnerabilities := []*report.Vulnerability{}
	rv := make(map[string]*report.Vulnerability)
	for _, v := range nucleiFindings {
		findingRow := map[string]string{
			"Template":    v.TemplateID,
			"MatcherName": v.MatcherName,
			"Matched":     v.Matched,
		}
		extractedResults := false
		if len(v.ExtractedResults) > 0 {
			extractedResults = true
		}
		resultRow := map[string]string{
			"References": strings.Join(v.ExtractedResults, "<br>"),
		}
		if vf, ok := rv[v.TemplateID]; ok {
			vf.Resources[0].Rows = append(vf.Resources[0].Rows, findingRow)
			if extractedResults {
				vf.Resources[1].Rows = append(vf.Resources[1].Rows, resultRow)
			}
			continue
		}
		recommendations := []string{v.Info.Remediation}
		if v.Info.Remediation == "" {
			recommendations = []string{
				"The check does not provide specific recommendations for this issue.",
				"Take a look to reference links (if any) for further details about the finding.",
			}
		}
		var vuln = report.Vulnerability{
			AffectedResource: v.Matched,
			CWEID:            getCWEID(v.Info.Classification.CWEID),
			Summary:          v.Info.Name,
			Description:      v.Info.Description,
			Details:          generateDetails(target, v.Template),
			Score:            getScore(v.Info.Severity),
			References:       v.Info.Reference,
			Recommendations:  recommendations,
			Labels:           []string{"nuclei", "issue"},
		}

		findingResources := report.ResourcesGroup{
			Name: "Finding",
			Header: []string{
				"Template",
				"MatcherName",
				"Matched",
			},
			Rows: []map[string]string{findingRow},
		}
		resultResources := report.ResourcesGroup{
			Name: "Results",
			Header: []string{
				"References",
			},
		}
		vuln.Resources = append(vuln.Resources, findingResources)
		vuln.Resources = append(vuln.Resources, resultResources)
		if extractedResults {
			vuln.Resources[1].Rows = append(vuln.Resources[1].Rows, resultRow)
		}
		rv[v.TemplateID] = &vuln
	}

	for _, v := range rv {
		// Compute fingerprint.
		findingsTableRows := v.Resources[0].Rows
		fpValueMap := make(map[string]void)
		for _, row := range findingsTableRows {
			for _, value := range row {
				fpValueMap[value] = void{}
			}
		}
		fpValueSlice := []string{}
		for k := range fpValueMap {
			fpValueSlice = append(fpValueSlice, k)
		}

		resultTableRows := v.Resources[1].Rows
		for _, row := range resultTableRows {
			for _, value := range row {
				fpValueSlice = append(fpValueSlice, value)
			}
		}

		// Remove result resources table if there are no rows.
		if len(resultTableRows) == 0 {
			v.Resources = []report.ResourcesGroup{v.Resources[0]}
		}

		sort.Strings(fpValueSlice)
		v.Fingerprint = helpers.ComputeFingerprint(fmt.Sprintf("%s", fpValueSlice))
		vulnerabilities = append(vulnerabilities, v)
	}

	return vulnerabilities
}

func runNuclei(nucleiArgs []string) ([]ResultEvent, error) {
	cmdSucceed := []bool{}
	nucleiFindings := []ResultEvent{}
	output, err := runNucleiCmd(nucleiArgs)
	if err != nil {
		return nucleiFindings, fmt.Errorf("nuclei execution failed: %w", err)
	}

	if len(output) == 0 {
		logger.Infof("no vulnerabilities found")
		return nucleiFindings, nil
	}

	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		var v ResultEvent
		err := json.Unmarshal(scanner.Bytes(), &v)
		if err != nil {
			logger.Errorf("unable to unmarshal vulnerability [%s]: %s", scanner.Text(), err)
			cmdSucceed = append(cmdSucceed, false)
			continue
		}
		nucleiFindings = append(nucleiFindings, v)
		cmdSucceed = append(cmdSucceed, true)
	}

	for _, succeed := range cmdSucceed {
		if succeed {
			return nucleiFindings, nil
		}
	}

	return nucleiFindings, nil
}

func buildNucleiScanCmdArgs(target string, opt options) []string {
	// Build arguments.
	nucleiArgs := []string{
		"-duc", // Disable automatic updates.
		"-target", target,
		"-c", "20",
		"-j",
		"-silent",
		"-no-meta",
		"-H", userAgent,
	}

	// Include only selected severities.
	if len(opt.Severities) > 0 {
		selectedSeverities := strings.Join(opt.Severities, ",")
		logger.Infof("selected severities: %s", selectedSeverities)
		severities := []string{"-severity", selectedSeverities}
		nucleiArgs = append(nucleiArgs, severities...)
	}

	// Include selected templates.
	if len(opt.TemplateInclusionList) > 0 {
		t := strings.Join(opt.TemplateInclusionList, ",")
		logger.Infof("included templates: %s", t)
		tArg := []string{"-t", t}
		nucleiArgs = append(nucleiArgs, tArg...)
	}

	// Exclude selected templates.
	if len(opt.TemplateExclusionList) > 0 {
		et := strings.Join(opt.TemplateExclusionList, ",")
		logger.Infof("excluded templates: %s", et)
		etArg := []string{"-et", et}
		nucleiArgs = append(nucleiArgs, etArg...)
	}

	// Include selected tags.
	if len(opt.TagInclusionList) > 0 {
		tags := strings.Join(opt.TagInclusionList, ",")
		logger.Infof("included tags: %s", tags)
		tagsArg := []string{"-tags", tags}
		nucleiArgs = append(nucleiArgs, tagsArg...)
	}

	// Exclude selected tags.
	if len(opt.TagExclusionList) > 0 {
		etags := strings.Join(opt.TagExclusionList, ",")
		logger.Infof("included tags: %s", etags)
		etagsArg := []string{"-etags", etags}
		nucleiArgs = append(nucleiArgs, etagsArg...)
	}

	logger.Debugf("nuclei scan command args: [%s]", nucleiArgs)

	return nucleiArgs
}

func generateDetails(target, template string) string {
	details := []string{
		"Run the following command to get the findings from your computer:",
		fmt.Sprintf(`
	docker run -it --rm projectdiscovery/nuclei -u %s -t %s`, target, template,
		),
	}
	return strings.Join(details, "\n")
}

func getScore(severity string) float32 {
	severity = strings.ToLower(severity)
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

func getCWEID(cwdid []string) uint32 {
	// Only returning CWEID if the template reports only one CWDID.
	if len(cwdid) != 1 {
		return 0
	}
	re := regexp.MustCompile("[0-9]+")
	cweIdString := re.FindString(cwdid[0])
	cweIdFound, _ := strconv.ParseUint(cweIdString, 10, 32)
	return uint32(cweIdFound)
}
