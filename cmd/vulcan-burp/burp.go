package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
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
	scanPollingInterval           = 30 // In seconds.
)

// Runner defines the check interface.
type Runner interface {
	Run(ctx context.Context) (err error)
}

type runner struct {
	burpCli    *resturp.Resturp
	burpScanID uint
	delete     bool
	ctx        context.Context
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
			r.burpCli.DeleteScan(r.burpScanID)
		}
		logger.Infof("cleanup process finished")
	}()

	scanStatus, err := r.burpCli.GetScanStatus(r.burpScanID)
	if err != nil {
		logger.Warnf("could't get scan status: %s", err)
		return
	}

	// If we reach here and the scan is not in a terminal status something went
	// wrong and we should try to cancel the scan in Burp.
	if !scanTerminalStatus[scanStatus.Status] {
		r.burpCli.CancelScan(r.burpScanID)
	}
}

func (r *runner) Run(ctx context.Context, target, assetType, optJSON string, state checkstate.State) (err error) {
	r.ctx = ctx
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

	apiToken, present := os.LookupEnv(burpAPITokenEnv)
	if !present {
		return ErrNoBurpAPIToken
	}

	baseURL, present := os.LookupEnv(burpBaseURLEnv)
	if !present {
		return ErrNoBurpBaseURL
	}

	scanConfig, present := os.LookupEnv(burpScanConfigEnv)
	if !present {
		return ErrNoBurpScanConfig
	}

	// InsecureSkipVerify should be set only for local testing.
	apiInsecureSkipVerifyStr, _ := os.LookupEnv(burpInsecureSkipVerifyEnv)
	apiInsecureSkipVerify, err := strconv.ParseBool(apiInsecureSkipVerifyStr)
	if err != nil {
		apiInsecureSkipVerify = defaultBurpInsecureSkipVerify
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
		// given existing Brup scan ID.
		// This is not intended to be used running in production, only
		// for local testing.
		logger.Infof("extracting vulnerabilities from an existing scan with ID [%d]", opt.ScanID)
		s, err = r.burpCli.GetScanStatus(opt.ScanID)
	} else {
		configs := strings.Split(scanConfig, ";")
		for i := range configs {
			configs[i] = strings.TrimSpace(configs[i])
		}
		logger.Infof("scanning with config %+v", configs)
		logger.Info("launching Burp scan")
		r.burpScanID, err = r.burpCli.LaunchScan(target, configs)
		if err != nil {
			return err
		}
		s, err = waitScanFinished(r)
	}
	if err != nil {
		return err
	}
	defs, err := r.burpCli.GetIssueDefinitions()
	if err != nil {
		return err
	}
	vulns := fillVulns(s.IssueEvents, defs)
	state.AddVulnerabilities(vulns...)

	return nil
}

func waitScanFinished(r *runner) (*resturp.ScanStatus, error) {
	t := time.NewTicker(scanPollingInterval * time.Second)
	var (
		err error
		s   *resturp.ScanStatus
	)

LOOP:
	for {
		select {
		case <-r.ctx.Done():
			logger.Infof("ctx.Done")
			t.Stop()
			return nil, r.ctx.Err()
		case <-t.C:
			s, err = r.burpCli.GetScanStatus(r.burpScanID)
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

	// Group vulnerabilities per AffectedResource.
	vAR := make(map[string]map[string][]int)
	for i, e := range ievents {
		issueId := strconv.Itoa(int(e.Issue.TypeIndex))
		issueDefinition, found := defsIndex[issueId]
		if !found {
			logger.Errorf("Burp issue [%d] not found in Burp issue definition list", issueId)
			continue
		}
		if v, found := vAR[issueDefinition.Name]; !found {
			affectedResourceVulnerabilityGroup := map[string][]int{
				e.Issue.Path: {i},
			}
			vAR[issueDefinition.Name] = affectedResourceVulnerabilityGroup
		} else {
			if ar, arFound := v[e.Issue.Path]; !arFound {
				v[e.Issue.Path] = []int{i}
			} else {
				ar = append(ar, i)
				v[e.Issue.Path] = ar
			}
		}
	}

	var vulns []report.Vulnerability
	for _, v := range vAR {
		for affectedResource, findings := range v {
			vuln := report.Vulnerability{}
			vulnIDs := []string{}
			for i, idexFinding := range findings {
				e := ievents[idexFinding]
				vulnIDs = append(vulnIDs, e.ID)
				issueDefinition, _ := defsIndex[strconv.Itoa(int(e.Issue.TypeIndex))]
				if i == 0 {
					vuln.Summary = issueDefinition.Name
					vuln.Description = issueDefinition.Description
					vuln.Recommendations = []string{issueDefinition.Remediation}
					vuln.Labels = []string{"web"}
					vuln.AffectedResource = affectedResource
					vuln.Score = severityToScore(e.Issue.Severity)
					vuln.Resources = []report.ResourcesGroup{
						{
							Name: "Found In",
							Header: []string{
								"Ref.",
								"Path",
								"Confidence",
								"CWEs",
							},
							Rows: []map[string]string{},
						},
						{
							Name: "Details",
							Header: []string{
								"Ref.",
								"Finding Details",
							},
							Rows: []map[string]string{},
						},
					}
					if issueDefinition.References != "" {
						vuln.Recommendations[0] = vuln.Recommendations[0] + issueDefinition.References
					}
					if vuln.Score == 0 {
						vuln.Labels = append(vuln.Labels, "informational")
					} else {
						vuln.Labels = append(vuln.Labels, confidenceToLabel(e.Issue.Confidence))
					}
				}
				rowFoundIn := map[string]string{
					"Ref.":       strconv.Itoa(i),
					"Path":       e.Issue.Path,
					"Confidence": e.Issue.Confidence,
					"CWEs":       issueDefinition.VulnerabilityClassifications,
				}
				vuln.Resources[0].Rows = append(vuln.Resources[0].Rows, rowFoundIn)
				if e.Issue.Description != "" {
					rowDetails := map[string]string{
						"Ref.":            strconv.Itoa(i),
						"Finding Details": e.Issue.Description,
					}
					vuln.Resources[1].Rows = append(vuln.Resources[1].Rows, rowDetails)
				}
			}
			// If vulnerability does not provide details then remove from resources table.
			if len(vuln.Resources[1].Rows) == 0 {
				vuln.Resources = vuln.Resources[:len(vuln.Resources)-1]
			}
			sort.Strings(vulnIDs)
			vulnID := computeVulnerabilityID(vuln.AffectedResource, vuln.AffectedResource, vulnIDs)
			vuln.ID = vulnID
			vulns = append(vulns, vuln)
		}
	}
	return vulns
}

func computeVulnerabilityID(target, affectedResource string, elems ...interface{}) string {
	h := sha256.New()

	fmt.Fprintf(h, "%s - %s", target, affectedResource)

	for _, e := range elems {
		fmt.Fprintf(h, " - %v", e)
	}

	return fmt.Sprintf("%x", h.Sum(nil))
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
