package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"os"
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
	scanPollingInterval           = 15 // In seconds.
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
	r.delete = opt.ScanID == 0 && !opt.SkipDeleteScan
	logger.Infof("Burp scan summary deletion after finish set to [%t]", r.delete)

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
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: apiInsecureSkipVerify},
	}
	client := &http.Client{Transport: tr}
	r.burpCli, err = resturp.New(client, baseURL, apiToken, logger)
	if err != nil {
		return err
	}

	// If a scan ID is specified try to generate the vulns from the
	// given existing Brup scan ID.
	// This is not intended to be used running in production, only
	// for local testing.
	if opt.ScanID != 0 {
		logger.Infof("extracting vulnerabilities from an existing scan with ID [%d]", opt.ScanID)
		s, err := r.burpCli.GetScanStatus(opt.ScanID)
		if err != nil {
			return err
		}
		if s.Status != "succeeded" {
			return errors.New("scan_id provided in options not found")
		}
		defs, err := r.burpCli.GetIssueDefinitions()
		if err != nil {
			return err
		}
		vulns := fillVulns(s.IssueEvents, defs)
		state.AddVulnerabilities(vulns...)
		return nil
	}

	configs := strings.Split(scanConfig, ";")
	for i := range configs {
		configs[i] = strings.TrimSpace(configs[i])
	}
	logger.Infof("scanning with config %+v", configs)

	r.burpScanID, err = r.burpCli.LaunchScan(target, configs)
	if err != nil {
		return err
	}
	s, err := waitScanFinished(r)
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
	var cvulns = make(map[string]report.Vulnerability)
	for _, i := range ievents {
		// TODO: Check the issue exists in the index, and return an error if
		// it doesn't.
		id := strconv.Itoa(int(i.Issue.TypeIndex))
		def := defsIndex[id]
		v := cvulns[id]
		v = fillVuln(i.Issue, def, v)
		cvulns[id] = v
	}
	var vulns []report.Vulnerability
	for _, v := range cvulns {
		v := v
		vulns = append(vulns, v)
	}
	return vulns
}

func fillVuln(i resturp.Issue, def resturp.IssueDefinition, v report.Vulnerability) report.Vulnerability {
	if v.Summary == "" {
		v = report.Vulnerability{}
		// We assume the severity is the same in all the paths the vulns has
		// been found.
		v.Summary = def.Name
		v.Score = severityToScore(i.Severity)
		v.Recommendations = []string{def.Remediation}
		v.Description = def.Description
		v.Resources = []report.ResourcesGroup{
			{
				Name: "Found In",
				Header: []string{
					"Path",
					"Confidence",
					"Description",
				},
				Rows: []map[string]string{},
			},
		}
	}
	score := severityToScore(i.Severity)
	if score > v.Score {
		v.Score = score
	}
	row := map[string]string{
		"Path":        i.Path,
		"Confidence":  i.Confidence,
		"Description": i.Description,
	}
	v.Resources[0].Rows = append(v.Resources[0].Rows, row)
	return v
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
