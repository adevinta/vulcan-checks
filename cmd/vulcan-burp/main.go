package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	check "github.com/adevinta/vulcan-check-sdk"
	"github.com/adevinta/vulcan-check-sdk/helpers"
	"github.com/adevinta/vulcan-check-sdk/state"
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
	scanPollingInterval           = 10 // In seconds.
)

var (
	checkName = "vulcan-burp"
	logger    = check.NewCheckLog(checkName)
)

// Options defines the possible options to be received by the check.
type Options struct {
	ScanID         uint `json:"scan_id"`
	SkipDeleteScan bool `json:"skip_delete_scan"`
}

func main() {
	c := check.NewCheckFromHandler(checkName, run)
	c.RunAndServe()
}

func run(ctx context.Context, target string, assetType string, optJSON string, state state.State) error {
	var opt Options
	if optJSON != "" {
		if err := json.Unmarshal([]byte(optJSON), &opt); err != nil {
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
	c, err := resturp.New(client, baseURL, apiToken, logger)
	if err != nil {
		return err
	}

	// If a scan ID is specified try to generate the vulns from the
	// given existing scan ID.
	// This is not intended to be used running in production, only
	// for local testing.
	if opt.ScanID != 0 {
		s, err := c.GetScanStatus(opt.ScanID)
		if err != nil {
			return err
		}
		defs, err := c.GetIssueDefinitions()
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

	id, err := c.LaunchScan(target, configs)
	// Delete scan summary from Burp platform unless instruct for
	// non do it or if we are reusing a Burp scan ID for testing.
	if id != 0 && opt.ScanID == 0 && !opt.SkipDeleteScan {
		defer c.DeleteScan(id)
	}
	if err != nil {
		return err
	}
	s, err := waitScanFinished(id, c)
	if err != nil {
		return err
	}
	defs, err := c.GetIssueDefinitions()
	if err != nil {
		return err
	}
	vulns := fillVulns(s.IssueEvents, defs)
	state.AddVulnerabilities(vulns...)
	return nil
}

func waitScanFinished(ID uint, c *resturp.Resturp) (*resturp.ScanStatus, error) {
	t := time.NewTicker(scanPollingInterval * time.Second)
	var (
		err error
		s   *resturp.ScanStatus
	)

LOOP:
	for {
		select {
		case <-t.C:
			s, err = c.GetScanStatus(ID)
			if err != nil {
				break LOOP
			}
			if s.Status == "succeeded" {
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

func parseCredentials(credentials string) (user string, password string) {
	parts := strings.Split(credentials, ":")
	if len(parts) < 1 {
		return
	}
	user = parts[0]
	if len(parts) < 2 {
		return
	}
	password = parts[1]
	return
}
