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
	"strings"

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

	asset, err := r.findAsset(ctx, target)
	if err != nil {
		return err
	}

	fmt.Printf("ASSET:\n%+v\n", asset)

	findings, err := r.getAssetFindings(ctx, target)
	if err != nil {
		return err
	}
	fmt.Printf("FINDINGS:\n%+v\n", findings)

	/*
		vulns, err := r.addVulnerabilities(*scanDetail, target)
		if err != nil {
			return err
		}

		state.AddVulnerabilities(vulns...)
	*/
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

func (r *runner) addVulnerabilities(scan restuss.ScanDetail, target string) ([]report.Vulnerability, error) {
	if len(scan.Vulnerabilities) <= 0 {
		return nil, nil
	}

	vulns := []report.Vulnerability{}
	for _, nessusVulnerability := range scan.Vulnerabilities {
		if len(scan.Hosts) == 0 {
			logger.Errorf("Hosts array is empty")
			continue
		}

		hostID := scan.Hosts[0].ID
		vulcanVulnerabilities, err := r.translateFromNessusToVulcan(hostID, target, nessusVulnerability)
		if err != nil {
			logger.Errorf("Error reading nessusVulnerability[%v] :%v", nessusVulnerability.PluginName, err)
			continue
		}
		vulns = append(vulns, vulcanVulnerabilities...)
	}
	return vulns, nil
}

// translateFromNessusToVulcan converts the vulnerabilities reported by Nessus
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
func (r *runner) translateFromNessusToVulcan(hostID int64, target string, nessusVulnerability restuss.Vulnerability) ([]report.Vulnerability, error) {
	p, err := r.nessusCli.GetPluginByID(nessusVulnerability.PluginID)
	if err != nil {
		return nil, err
	}

	vulcanVulnerability := report.Vulnerability{
		Summary: p.Name,
		Labels:  []string{"issue", "nessus"},
	}

	// There might be more than one attribute with the same name. For example
	// "cwe", "solution" or "see_also".
	attributesMap := make(map[string][]string)
	for _, attr := range p.Attributes {
		attributesMap[attr.Name] = append(attributesMap[attr.Name], attr.Value)
	}

	// Tenable is now using CVSS v3 score as their default scoring system. In
	// order to match the score of the vulnerabilities we report with the score
	// Tenable reports in the tenable.io UI, we will default to the CVSS v3
	// Nessus score if available, falling back to the already used CVSS base
	// score otherwise.
	scores := attributesMap["cvss3_base_score"]
	if len(scores) < 1 {
		scores = attributesMap["cvss_base_score"]
	}
	// There might be the case where Nessus doesn't provide a CVSS score and in
	// that case we will use the Severity they report.
	if len(scores) > 0 {
		score, errParse := strconv.ParseFloat(scores[0], 32)
		if errParse != nil {
			return nil, errParse
		}

		vulcanVulnerability.Score = float32(score)
	} else {
		vulcanVulnerability.Score = report.ScoreSeverity(report.SeverityRank(nessusVulnerability.Severity))
	}

	// NOTE: even that Nessus plugins might be reporting more than one CWE per
	// vulnerability our vulcan-report just supports one value per
	// vulnerability, so we are taking just the first one returned by Nessus.
	if cwes := attributesMap["cwe"]; len(cwes) > 0 {
		cweid, errAtoi := strconv.Atoi(cwes[0])
		if errAtoi != nil {
			return nil, errAtoi
		}
		vulcanVulnerability.CWEID = uint32(cweid)
	}

	if desc := attributesMap["description"]; len(desc) > 0 {
		vulcanVulnerability.Description = desc[0]
	}
	if syn := attributesMap["synopsis"]; len(syn) > 0 {
		vulcanVulnerability.ImpactDetails = syn[0]
	}

	for _, sol := range attributesMap["solution"] {
		vulcanVulnerability.Recommendations = append(vulcanVulnerability.Recommendations, sol)
	}

	for _, ref := range attributesMap["see_also"] {
		references := strings.Split(ref, "\n")
		vulcanVulnerability.References = append(vulcanVulnerability.References, references...)
	}

	pluginOutput, err := r.nessusCli.GetPluginOutput(1, hostID, nessusVulnerability.PluginID)
	if err != nil {
		return nil, err
	}

	// In the case Nessus doesn't provide runtime/context information there's
	// no much we can state in addition from what the plugin itself describes.
	if len(pluginOutput.Output) < 1 {
		// As there are no ports specified in the Output, we can't be more
		// specific for the affected resource than the whole target.
		vulcanVulnerability.AffectedResource = target
		// As we don't have context information from the Output, at least we
		// use the score as a fingerprint.
		vulcanVulnerability.Fingerprint = helpers.ComputeFingerprint(vulcanVulnerability.Score)

		return []report.Vulnerability{vulcanVulnerability}, nil
	}

	var vulnerabilities []report.Vulnerability
	// Create a new vulnerability per each Output and Port (in case they
	// exist).  Port format seems to be 'port / protocol / service'. For
	// example: '25 / tcp / smtp'.  In case the Output is not associated to a
	// specific port, Nessus seems to be using '0 / tcp'.
	for _, output := range pluginOutput.Output {
		v := vulcanVulnerability
		v.Details = output.Output

		mapPorts, ok := output.Ports.(map[string]interface{})
		// Only parse the mapPorts if we get the right type.
		if !ok || len(mapPorts) < 1 {
			logger.Warnf("unexpected type for Output.Ports: %#v", output.Ports)

			// Again, if there are no ports specified we can't be more precise
			// than using the target as the affected resource.
			v.AffectedResource = target
			// Apart from the score, we can use the Details as a fingerprint,
			// that is supposed to give the context of the vulnerability in the
			// scanned target.
			//
			// NOTE: in the examples we analyzed the Details field seemed to be
			// stable between executions, but there might be plugins where this
			// information changes more often than expected.
			v.Fingerprint = helpers.ComputeFingerprint(v.Score, v.Details)

			vulnerabilities = append(vulnerabilities, v)

			continue
		}

		for portInformation := range mapPorts {
			v := v

			parts := strings.Split(portInformation, " / ")
			if len(parts) > 2 {
				networkResource := map[string]string{
					"Hostname": target,
					"Port":     parts[0],
					"Protocol": parts[1],
					"Service":  parts[2],
				}
				v.Resources = []report.ResourcesGroup{
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

			v.AffectedResource = portInformation
			v.Fingerprint = helpers.ComputeFingerprint(v.Score, v.Details, v.Resources)

			vulnerabilities = append(vulnerabilities, v)
		}
	}

	return vulnerabilities, nil
}
