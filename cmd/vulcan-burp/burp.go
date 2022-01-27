package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/adevinta/vulcan-check-sdk/helpers"
	checkstate "github.com/adevinta/vulcan-check-sdk/state"
	"github.com/adevinta/vulcan-checks/cmd/vulcan-burp/resturp"
	report "github.com/adevinta/vulcan-report"
)

const (
	burpAPITokenEnv           = "BURP_API_TOKEN"
	burpBaseURLEnv            = "BURP_BASE_URL"
	burpInsecureSkipVerifyEnv = "BURP_INSECURE_SKIP_VERIFY"
	burpScanConfigEnv         = "BURP_SCAN_CONFIG"

	defaultBurpInsecureSkipVerify = false
	defaultBurpScanConfig         = "Crawl strategy - fastest;Audit checks - all except time-based detection methods;Audit checks - light active;Never stop audit due to application errors"
	scanPollingInterval           = 30 // In seconds.
)

type runner struct {
	burpCli    *resturp.Resturp
	burpScanID uint
	delete     bool
}

var scanTerminalStatus = map[string]bool{
	"succeeded": true,
	"failed":    true,
}

// CleanUp is called by the sdk when the check finishes or a check abort
// operation has been requested. We must perform clean up tasks at this point.
func (r *runner) CleanUp(ctx context.Context, target, assetType, opts string) {
	if r.burpScanID == 0 {
		// Nothing to handle.
		return
	}
	logger.Infof("starting cleanup process")
	defer func() {
		logger.Infof("Burp scan summary deletion after finish set to [%t]", r.delete)
		if r.delete {
			r.burpCli.DeleteScan(ctx, r.burpScanID)
		}
		logger.Infof("cleanup process finished")
	}()

	scanStatus, err := r.burpCli.GetScanStatus(ctx, r.burpScanID)
	if err != nil {
		logger.Warnf("could't get scan status: %s", err)
		return
	}

	// If we reach here and the scan is not in a terminal status something went
	// wrong and we should try to cancel the scan in Burp.
	if !scanTerminalStatus[scanStatus.Status] {
		r.burpCli.CancelScan(ctx, r.burpScanID)
	}
}

func (r *runner) Run(ctx context.Context, target, assetType, optJSON string, state checkstate.State) (err error) {
	var opt Options
	if optJSON != "" {
		if err := json.Unmarshal([]byte(optJSON), &opt); err != nil {
			return err
		}
	}
	// Scan summary will be deleted after finish unless a scan_id has been
	// provided in the Opts. or if skip_delete_scan is set true in the Opts.
	r.delete = !(opt.ScanID != 0 || opt.SkipDeleteScan)

	isReachable, err := helpers.IsReachable(target, assetType, nil)
	if err != nil {
		logger.Warnf("Can not check asset reachability: %v", err)
	}
	if !isReachable {
		return checkstate.ErrAssetUnreachable
	}

	apiToken := os.Getenv(burpAPITokenEnv)
	if apiToken == "" {
		return ErrNoBurpAPIToken
	}

	baseURL := os.Getenv(burpBaseURLEnv)
	if baseURL == "" {
		return ErrNoBurpBaseURL
	}
	baseURL = strings.TrimSuffix(baseURL, "/")

	scanConfig := os.Getenv(burpScanConfigEnv)
	if scanConfig == "" {
		scanConfig = defaultBurpScanConfig
	}

	// InsecureSkipVerify should be set only for local testing.
	apiInsecureSkipVerify := defaultBurpInsecureSkipVerify
	apiInsecureSkipVerifyStr := os.Getenv(burpInsecureSkipVerifyEnv)
	if apiInsecureSkipVerifyStr != "" {
		apiInsecureSkipVerify, err = strconv.ParseBool(apiInsecureSkipVerifyStr)
		if err != nil {
			apiInsecureSkipVerify = defaultBurpInsecureSkipVerify
		}
	}
	if apiInsecureSkipVerify {
		logger.Warn("contacting Burp API with `InsecureSkipVerify` set to true")
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: apiInsecureSkipVerify},
	}
	client := &http.Client{Transport: tr}
	r.burpCli, err = resturp.New(client, baseURL, apiToken, logger)
	if err != nil {
		return err
	}

	var s *resturp.ScanStatus
	if opt.ScanID != 0 {
		// If a scan ID is specified try to generate the vulns from the
		// given existing Burp scan ID.
		// This is not intended to be used running in production, only
		// for local testing.
		logger.Infof("extracting vulnerabilities from an existing scan with ID [%d]", opt.ScanID)
		s, err = r.burpCli.GetScanStatus(ctx, opt.ScanID)
	} else {
		configs := strings.Split(scanConfig, ";")
		for i := range configs {
			configs[i] = strings.TrimSpace(configs[i])
		}
		logger.Infof("scanning with config %+v", configs)
		logger.Info("launching Burp scan")
		r.burpScanID, err = r.burpCli.LaunchScan(ctx, target, configs)
		if err != nil {
			return err
		}
		s, err = r.WaitScanFinished(ctx)
	}
	if err != nil {
		return err
	}
	defs, err := r.burpCli.GetIssueDefinitions(ctx)
	if err != nil {
		return err
	}
	vulns := fillVulns(s.IssueEvents, defs)
	state.AddVulnerabilities(vulns...)

	return nil
}

func (r *runner) WaitScanFinished(ctx context.Context) (*resturp.ScanStatus, error) {
	t := time.NewTicker(scanPollingInterval * time.Second)
	var (
		err error
		s   *resturp.ScanStatus
	)

LOOP:
	for {
		select {
		case <-ctx.Done():
			logger.Infof("ctx.Done")
			t.Stop()
			return nil, ctx.Err()
		case <-t.C:
			s, err = r.burpCli.GetScanStatus(ctx, r.burpScanID)
			if err != nil {
				break LOOP
			}
			logger.Infof("polling. Scan status [%s]", s.Status)
			if s.Status == "succeeded" {
				break LOOP
			}
			// TODO: A failed scan provides a "partial" vulnerability summary.
			// We should evaluate if is better to return a partial summary or
			// is better to consider always only complete/successfully scans.
			// For the sake of consistency for now we are considering only
			// complete/successfully scans.
			if s.Status == "failed" {
				err = errors.New("scan finished unsuccessfully")
				logger.Errorf("Burp scan ID [%d]: %s", r.burpScanID, err)
				break LOOP
			}
			break
		}
	}
	return s, err
}

func fillVulns(ievents []resturp.IssueEvent, defs []resturp.IssueDefinition) []report.Vulnerability {
	// Index definitions by issue type ID.
	defsIndex := map[string]resturp.IssueDefinition{}
	for _, d := range defs {
		defsIndex[d.IssueTypeID] = d
	}

	vulnsMap := make(map[string]report.Vulnerability)
	for _, i := range ievents {
		issueId := strconv.FormatInt(i.Issue.TypeIndex, 10)
		issueDefinition, found := defsIndex[issueId]
		if !found {
			logger.Errorf("Burp issue [%s] not found in Burp issue definition list", issueId)
			continue
		}

		if v, ok := vulnsMap[issueDefinition.Name]; ok {
			// Vulnerability already exists in vulnsMap.
			score := severityToScore(i.Issue.Severity)
			if v.Score < score {
				v.Score = score
			}
			row := map[string]string{
				"Path":       i.Issue.Path,
				"Confidence": i.Issue.Confidence,
				"CWEs":       issueDefinition.VulnerabilityClassifications,
			}
			v.Resources[0].Rows = append(v.Resources[0].Rows, row)
			vulnsMap[issueDefinition.Name] = v
			continue
		}
		// New vulnerability in vulnsMap.
		vuln := report.Vulnerability{
			Summary:         issueDefinition.Name,
			Description:     issueDefinition.Description,
			Recommendations: []string{issueDefinition.Remediation},
			Score:           severityToScore(i.Issue.Severity),
			Labels:          []string{"web", "burp"},
			Details:         i.Issue.Description,
			Resources: []report.ResourcesGroup{
				{
					Name: "Found In",
					Header: []string{
						"Path",
						"Confidence",
						"CWEs",
					},
					Rows: []map[string]string{},
				},
			},
		}
		row := map[string]string{
			"Path":       i.Issue.Path,
			"Confidence": i.Issue.Confidence,
			"CWEs":       issueDefinition.VulnerabilityClassifications,
		}
		vuln.Resources[0].Rows = append(vuln.Resources[0].Rows, row)
		if issueDefinition.References != "" {
			hrefRegExp := regexp.MustCompile(`<a href="([^"]*)"`)
			referenceLinkList := hrefRegExp.FindAllSubmatch([]byte(issueDefinition.References), -1)
			for _, r := range referenceLinkList {
				if len(r) > 1 {
					vuln.References = append(vuln.References, string(r[1]))
				}
			}
		}
		if vuln.Score == 0 {
			vuln.Labels = append(vuln.Labels, "informational")
		} else {
			vuln.Labels = append(vuln.Labels, confidenceToLabel(i.Issue.Confidence))
		}
		vulnsMap[issueDefinition.Name] = vuln
	}

	// Target vulnerability array.
	vulns := []report.Vulnerability{}
	for _, v := range vulnsMap {
		// Compute fingerprint.
		affectedPaths := []string{}
		for _, affectedPathMap := range v.Resources[0].Rows {
			if path, ok := affectedPathMap["Path"]; ok {
				affectedPaths = append(affectedPaths, path)
			}
		}
		sort.Strings(affectedPaths)
		v.Fingerprint = helpers.ComputeFingerprint(v.Score, strings.Join(affectedPaths, "|"))

		// Append vulnerability to target vulnerability array.
		vulns = append(vulns, v)
	}

	return vulns
}

func severityToScore(risk string) float32 {
	switch risk {
	case "info":
		return report.SeverityThresholdNone
	case "low":
		return report.SeverityThresholdLow
	case "medium":
		return report.SeverityThresholdMedium
	case "high":
		return report.SeverityThresholdHigh
	default:
		return report.SeverityThresholdNone
	}
}

func confidenceToLabel(confidence string) string {
	switch confidence {
	case "certain":
		return "issue"
	}
	return "potential"
}
