/*
Copyright 2020 Adevinta
*/

package main

import (
	"context"
	"encoding/json"
	"os"
	"strings"

	"github.com/adevinta/vulcan-check-sdk/helpers/command"
)

const (
	prowlerCmd     = `prowler`
	reportFormat   = `json`
	reportName     = `report`
	reportLocation = `/home/prowler/output/report.json`
)

type prowlerReport []prowlerFinding

type prowlerFinding struct {
	AssessmentStartTime string `json:"AssessmentStartTime,omitempty"`
	FindingUniqueID     string `json:"FindingUniqueId,omitempty"`
	Provider            string `json:"Provider,omitempty"`
	CheckID             string `json:"CheckID,omitempty"`
	CheckTitle          string `json:"CheckTitle,omitempty"`
	CheckType           []any  `json:"CheckType,omitempty"`
	ServiceName         string `json:"ServiceName,omitempty"`
	SubServiceName      string `json:"SubServiceName,omitempty"`
	Status              string `json:"Status,omitempty"`
	StatusExtended      string `json:"StatusExtended,omitempty"`
	Severity            string `json:"Severity,omitempty"`
	ResourceType        string `json:"ResourceType,omitempty"`
	ResourceDetails     string `json:"ResourceDetails,omitempty"`
	Description         string `json:"Description,omitempty"`
	Risk                string `json:"Risk,omitempty"`
	RelatedURL          string `json:"RelatedUrl,omitempty"`
	Remediation         struct {
		Code struct {
			NativeIaC string `json:"NativeIaC,omitempty"`
			Terraform string `json:"Terraform,omitempty"`
			Cli       string `json:"CLI,omitempty"`
			Other     string `json:"Other,omitempty"`
		} `json:"Code,omitempty"`
		Recommendation struct {
			Text string `json:"Text,omitempty"`
			URL  string `json:"Url,omitempty"`
		} `json:"Recommendation,omitempty"`
	} `json:"Remediation,omitempty"`
	Compliance map[string][]string
	// Cisa                                         []string `json:"CISA,omitempty"`
	// Soc2                                         []string `json:"SOC2,omitempty"`
	// MITREATTACK                                  []string `json:"MITRE-ATTACK,omitempty"`
	// Gdpr                                         []string `json:"GDPR,omitempty"`
	// Hipaa                                        []string `json:"HIPAA,omitempty"`
	// GxP21CFRPart11                               []string `json:"GxP-21-CFR-Part-11,omitempty"`
	// GxPEUAnnex11                                 []string `json:"GxP-EU-Annex-11,omitempty"`
	// NIST800171Revision2                          []string `json:"NIST-800-171-Revision-2,omitempty"`
	// NIST80053Revision4                           []string `json:"NIST-800-53-Revision-4,omitempty"`
	// NIST80053Revision5                           []string `json:"NIST-800-53-Revision-5,omitempty"`
	// NISTCSF11                                    []string `json:"NIST-CSF-1.1,omitempty"`
	// AWSWellArchitectedFrameworkReliabilityPillar []string `json:"AWS-Well-Architected-Framework-Reliability-Pillar,omitempty"`
	// RBICyberSecurityFramework                    []string `json:"RBI-Cyber-Security-Framework,omitempty"`
	// Ffiec                                        []string `json:"FFIEC,omitempty"`
	// FedRampModerateRevision4                     []string `json:"FedRamp-Moderate-Revision-4,omitempty"`
	// FedRAMPLowRevision4                          []string `json:"FedRAMP-Low-Revision-4,omitempty"`
	// AWSFoundationalSecurityBestPractices         []string `json:"AWS-Foundational-Security-Best-Practices,omitempty"`
	// CIS14                                        []string `json:"CIS-1.4,omitempty"`
	// CIS15                                        []string `json:"CIS-1.5,omitempty"`
	// ISO270012013                                 []string `json:"ISO27001-2013,omitempty"`
	// CIS20                                        []string `json:"CIS-2.0,omitempty"`
	// AWSWellArchitectedFrameworkSecurityPillar    []string `json:"AWS-Well-Architected-Framework-Security-Pillar,omitempty"`
	// ENSRD2022                                    []string `json:"ENS-RD2022,omitempty"`
	// AWSAuditManagerControlTowerGuardrails        []string `json:"AWS-Audit-Manager-Control-Tower-Guardrails,omitempty"`
	Categories        []string `json:"Categories,omitempty"`
	DependsOn         []string `json:"DependsOn,omitempty"`
	RelatedTo         []string `json:"RelatedTo,omitempty"`
	Notes             string   `json:"Notes,omitempty"`
	Profile           any      `json:"Profile,omitempty"`
	AccountID         string   `json:"AccountId,omitempty"`
	OrganizationsInfo any      `json:"OrganizationsInfo,omitempty"`
	Region            string   `json:"Region,omitempty"`
	ResourceID        string   `json:"ResourceId,omitempty"`
	ResourceArn       string   `json:"ResourceArn,omitempty"`
	ResourceTags      map[string]string
}

/*
Command example:

	prowler -r eu-west-1 -g cislevel1 -T 3600 -M json -F report

Output available at /prowler/output/report.json
*/
func buildParams(region string, groups []string) []string {
	// TODO: Manage more than 1 group or restrict to one.
	params := []string{
		"--compliance", strings.Join(groups, ","),
		"-M", reportFormat,
		"-F", reportName,
		"--no-banner",
		"--ignore-exit-code-3",
	}
	if region != "" {
		params = append(params, "-f", region)
	} else {
		params = append(params, "-f", defaultAPIRegion)
	}
	return params
}

func runProwler(ctx context.Context, region string, groups []string) (*prowlerReport, error) {
	logger.Infof("using region: %+v, and groups: %+v", region, groups)
	params := buildParams(region, groups)

	version, _, err := command.Execute(ctx, logger, prowlerCmd, "-v")
	if err != nil {
		return nil, err
	}
	logger.Infof("prowler version: %s", version)

	output, status, err := command.Execute(ctx, logger, prowlerCmd, params...)
	if err != nil {
		return nil, err
	}
	logger.Infof("exit status: %v", status)
	logger.Debugf("prowler output: %s", output)

	fileReport, err := os.ReadFile(reportLocation)
	if err != nil {
		return nil, err
	}
	logger.Debugf("file report: %s", fileReport)

	out := prowlerReport{}
	err = json.Unmarshal(fileReport, &out)
	if err != nil {
		return nil, err
	}
	return &out, nil
}
