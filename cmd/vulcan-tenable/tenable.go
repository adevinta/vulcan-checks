/*
Copyright 2021 Adevinta
*/

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"

	log "github.com/sirupsen/logrus"

	"github.com/adevinta/restuss"
	"github.com/adevinta/vulcan-check-sdk/helpers"
	checkstate "github.com/adevinta/vulcan-check-sdk/state"
	report "github.com/adevinta/vulcan-report"
)

const (
	// Default asset tag.
	assetTag = `provider:vulcan`
)

// Runner executes a Tenable check.
type Runner interface {
	Run(ctx context.Context) (err error)
}

type runner struct {
	nessusCli *restuss.NessusClient
}

func (r *runner) Run(ctx context.Context, target, assetType, optJSON string, state checkstate.State) (err error) {
	var opt options
	if optJSON != "" {
		if err = json.Unmarshal([]byte(optJSON), &opt); err != nil {
			return err
		}
	}

	isReachable, err := helpers.IsReachable(target, assetType, nil)
	if err != nil {
		logger.Warnf("Can not check asset reachability: %v", err)
	}
	if !isReachable {
		return checkstate.ErrAssetUnreachable
	}

	basicAuth := opt.BasicAuth

	logger = logger.WithFields(log.Fields{
		"target": target,
	})
	err = r.auth(basicAuth)
	if err != nil {
		return err
	}

	_, err = r.findAsset(ctx, target)
	if err != nil {
		return err
	}

	findings, err := r.getAssetFindings(ctx, target)
	if err != nil {
		return err
	}

	vulns, err := r.addVulnerabilities(target, findings)
	if err != nil {
		return err
	}

	state.AddVulnerabilities(vulns...)

	return nil
}

func (r *runner) auth(basicAuth bool) error {
	var auth restuss.AuthProvider

	if basicAuth {
		auth = restuss.NewBasicAuthProvider(os.Getenv("NESSUS_USERNAME"), os.Getenv("NESSUS_PASSWORD"))
	} else {
		auth = restuss.NewKeyAuthProvider(os.Getenv("NESSUS_USERNAME"), os.Getenv("NESSUS_PASSWORD"))
	}

	cli, err := restuss.NewClient(auth, os.Getenv("NESSUS_ENDPOINT"), false)
	if err != nil {
		return fmt.Errorf("error creating restuss client: %+v", err)
	}
	r.nessusCli = cli
	return nil
}

func (r *runner) findAsset(ctx context.Context, name string) (restuss.Asset, error) {
	asset, err := r.nessusCli.GetAssetByName(ctx, name)
	if err != nil {
		return restuss.Asset{}, err
	}
	return *asset, nil
}

func (r *runner) getAssetFindings(ctx context.Context, name string) ([]restuss.Finding, error) {
	return r.nessusCli.GetFindingsByAssetName(ctx, name)
}

// CleanUp is called by the sdk when the check needs to be aborted in order to give the
// opportunity to clean up resources.
func (r *runner) CleanUp(ctx context.Context, target, assetType, opts string) {
}

// addVulnerabilities converts the vulnerabilities reported by Nessus
// into Vulcan vulnerabilities.
//
// The information of a Nessus vulnerability is spread in two different places:
//
// * The Nessus plugin (vulnerability) definition.
//
// * The output or execution context of that plugin against a concrete target.
//
// The plugin definition contains inherent information about the issue, like
// the summary/title, description, score, solution, references, etc. For
// example https://www.tenable.com/plugins/nessus/20007
//
// The output indicates runtime/execution context details, like the part of the
// target where the issue was found (i.e. TCP/UDP ports) and the matching
// information found to report the issue. For example for the `SSL Version 2
// and 3 Protocol Detection` plugin it reports information about the protocols
// and ciphersuites enabled for the target.
func (r *runner) addVulnerabilities(target string, findings []restuss.Finding) ([]report.Vulnerability, error) {
	var vulns []report.Vulnerability
	for _, finding := range findings {
		vuln := report.Vulnerability{
			Summary:         finding.Definition.Name,
			Description:     finding.Definition.Description,
			ImpactDetails:   finding.Definition.Synopsis,
			Recommendations: []string{finding.Definition.Solution},
			References:      finding.Definition.SeeAlso,
			Details:         finding.Output,
			Labels:          []string{"issue", "nessus"},
		}

		// NOTE: for retro-compatibility with the vulcan-nessus check findings,
		// we the description formatted as returned by the plugin endpoint, as
		// it differs in the format as the one returned by the findings
		// endpoint.
		pluginID, err := strconv.Atoi(finding.Definition.PluginID)
		if err != nil {
			return nil, err
		}
		p, err := r.nessusCli.GetPluginByID(int64(pluginID))
		if err != nil {
			return nil, err
		}
		for _, attr := range p.Attributes {
			if attr.Name == "description" {
				vuln.Description = attr.Value
				break
			}
		}

		// NOTE: for retro-compatibility with the vulcan-nessus check findings,
		// we use `n/a` when there is any recommendation.
		if len(vuln.Recommendations) == 1 && vuln.Recommendations[0] == "" {
			vuln.Recommendations[0] = "n/a"
		}

		// Tenable is now using CVSS v3 score as their default scoring system.
		// In order to match the score of the vulnerabilities we report with
		// the score Tenable reports in the tenable.io UI, we will default to
		// the CVSS v3 Nessus score if available, falling back to the already
		// used CVSS v2 base score otherwise, or Nessus Severity as a last
		// resort.
		if finding.Definition.CVSS3.BaseScore != nil {
			vuln.Score = *finding.Definition.CVSS3.BaseScore
		} else if finding.Definition.CVSS2.BaseScore != nil {
			vuln.Score = *finding.Definition.CVSS2.BaseScore
		} else {
			vuln.Score = report.ScoreSeverity(report.SeverityRank(finding.Severity))
		}

		// NOTE: even that Nessus plugins might be reporting more than one CWE
		// per vulnerability our vulcan-report just supports one value per
		// vulnerability, so we are taking just the first one returned by
		// Nessus.
		if len(finding.Definition.CWE) > 0 {
			cweid, errAtoi := strconv.Atoi(finding.Definition.CWE[0])
			if errAtoi != nil {
				return nil, errAtoi
			}
			vuln.CWEID = uint32(cweid)
		}

		// NOTE: for retro-compatibility with the vulcan-nessus check findings,
		// when there are no ports specificed in the finding we will use `0 /
		// PROTOCOL` as the affected resource instead of the whole target.
		if finding.Port == 0 {
			vuln.AffectedResource = fmt.Sprintf("%v / %v", finding.Port, finding.Protocol)
		} else {
			vuln.AffectedResource = fmt.Sprintf("%v / %v / %v", finding.Port, finding.Protocol, finding.Service)

			networkResource := map[string]string{
				"Hostname": target,
				"Port":     strconv.Itoa(finding.Port),
				"Protocol": finding.Protocol,
				"Service":  finding.Service,
			}
			vuln.Resources = []report.ResourcesGroup{
				report.ResourcesGroup{
					Name: "Network Resources",
					Header: []string{
						"Hostname",
						"Port",
						"Protocol",
						"Service",
					},
					Rows: []map[string]string{networkResource},
				},
			}
		}

		// Apart from the score, we can use the Details as a fingerprint, that
		// is supposed to give the context of the vulnerability in the scanned
		// target.
		//
		// NOTE: in the examples we analyzed the Details field seemed to be
		// stable between executions, but there might be plugins where this
		// information changes more often than expected.
		vuln.Fingerprint = helpers.ComputeFingerprint(vuln.Score, vuln.Details, vuln.Resources)

		vulns = append(vulns, vuln)
	}

	return vulns, nil
}
