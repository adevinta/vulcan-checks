package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
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
	nucleiCmd              = "./nuclei"
	nucleiTemplatePath     = "/root/nuclei-templates/"
	nucleiTemplateListJSON = "TEMPLATES-STATS.json"

	defaultTemplateExclusionList = []string{
		"fuzzing",
		"helpers",
		"miscellaneous",
		"workflows",
	}
)

type void struct{}

type options struct {
	SkipUpdateTemplates   bool     `json:"skip_update_templates"`
	Severities            []string `json:"severities"`
	TemplateInclusionList []string `json:"template_inclusion_list"`
	TemplateExclusionList []string `json:"template_exclusion_list"`
}

// TemplateList defines nuclei templates available.
type TemplateList struct {
	Directory []struct {
		Name  string `json:"name"`
		Count int    `json:"count"`
	} `json:"directory"`
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

	if !opt.SkipUpdateTemplates {
		_, err := runNucleiCmd([]string{"-update-templates"})
		if err != nil {
			return errors.New("nuclei update-templates command execution failed")
		}
	}

	logger.Debugf("templates path: %s%s", nucleiTemplatePath, nucleiTemplateListJSON)
	tl, err := templateList()
	if err != nil {
		return errors.New("unable to obtain nuclei template list")
	}
	availableTemplates := make(map[string]void)
	for _, t := range tl.Directory {
		availableTemplates[t.Name] = void{}
	}
	logger.Infof("available templates: %+v", availableTemplates)

	selectedTemplates := make(map[string]void)
	logger.Infof("included templates: %+v", opt.TemplateInclusionList)
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
	if len(opt.TemplateExclusionList) == 0 {
		logger.Info("no template exclusion list provided, applying default template exclusion list")
		opt.TemplateExclusionList = defaultTemplateExclusionList
	}
	logger.Infof("exclued templates: %+v", opt.TemplateExclusionList)

	for _, v := range opt.TemplateExclusionList {
		if _, ok := selectedTemplates[v]; ok {
			delete(selectedTemplates, v)
		}
	}

	logger.Infof("selected templates: %+v", selectedTemplates)
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
		"-no-meta",
		"-no-timestamp",
		"-H", userAgent,
	}

	// Include only selected severities.
	selectedSeverities := strings.Join(opt.Severities, ",")
	if len(opt.Severities) > 0 {
		logger.Infof("selected severities: %s", selectedSeverities)
		severities := []string{"-severity", selectedSeverities}
		nucleiArgs = append(nucleiArgs, severities...)
	}

	logger.Debugf("nuclei command args: [%s]", nucleiArgs)
	var nucleiVulns []ResultEvent
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
			var v ResultEvent
			err := json.Unmarshal(scanner.Bytes(), &v)
			if err != nil {
				logger.Errorf("unable to unmarshal vulnerability [%s]: %s", scanner.Text(), err)
				continue
			}
			nucleiVulns = append(nucleiVulns, v)
		}
	}
	// No vulnerabilities found. Return.
	if len(nucleiVulns) < 1 {
		logger.Info("no vulnerabilities found")
		return nil
	}
	logger.Infof("nuclei found [%d] vulnerabilities", len(nucleiVulns))

	rv := make(map[string]*report.Vulnerability)
	for _, v := range nucleiVulns {
		// Create resources table row.
		// Avoid store redundant information in the resources table.
		matched := v.Matched
		if matched == target {
			matched = ""
		}
		findingRow := map[string]string{
			"Template":    v.TemplateID,
			"MatcherName": v.MatcherName,
			"Matched":     matched,
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
			AffectedResource: target,
			CWEID:            getCWEID(v.Info.Classification.CWEID),
			Summary:          v.Info.Name,
			Description:      v.Info.Description,
			Details:          generateDetails(target, v.Template),
			Score:            getScore(v.Info.Severity),
			References:       v.Info.Reference,
			Recommendations:  recommendations,
			Labels:           []string{"nuclei", v.Type},
		}
		if strings.EqualFold(v.Info.Severity, "info") {
			vuln.Labels = append(vuln.Labels, "informational")
		} else {
			vuln.Labels = append(vuln.Labels, "issue")
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
		state.AddVulnerabilities(*v)
	}

	return nil
}

func templateList() (TemplateList, error) {
	var tl TemplateList
	data, err := ioutil.ReadFile(fmt.Sprintf("%s%s", nucleiTemplatePath, nucleiTemplateListJSON))
	if err != nil {
		return tl, err
	}
	err = json.Unmarshal(data, &tl)
	return tl, err
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
