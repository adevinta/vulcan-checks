package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	check "github.com/adevinta/vulcan-check-sdk"
	"github.com/adevinta/vulcan-check-sdk/state"
	"github.com/adevinta/vulcan-checks/cmd/vulcan-burp/resturp"
	report "github.com/adevinta/vulcan-report"
)

const (
	activeScanMode  = "active"
	passiveScanMode = "passive"
	burpEndPointEnv = "BURP_API_ENDPOINT"
)

var (
	checkName = "vulcan-burp"

	logger = check.NewCheckLog(checkName)

	// ErrNoBurpAPIEndPoint is returned by the check when the burp api url is
	// not defined.
	ErrNoBurpAPIEndPoint = errors.New("BURP_API_ENDPOINT env var must be set")

	// ErrInvalidScanMode is returned when an invalid scan mode was specified.
	ErrInvalidScanMode = errors.New("invalid scan mode")

	defaultTimeout = 300 * time.Minute
)

type options struct {
	ScanMode ScanMode `json:"vulcan_burp.scan_mode"`
	ScanID   uint     `json:"vulcan_burp.scan_id"`
}

// ScanMode possible scan modes are: "active" and "passive".
type ScanMode string

func (s ScanMode) toBurpConfigs() ([]string, error) {
	if s == "passive" || s == "" {
		return []string{"Crawl limit - 10 minutes", "Audit checks - passive"}, nil
	}

	if s == "active" {
		// return []string{"Crawl limit - 10 minutes", "Audit coverage - maximum"}, nil
		return []string{}, nil
	}

	return nil, fmt.Errorf("%w, mode specified was %s, only valid modes are: active, passive", ErrInvalidScanMode, s)
}

func buildOptions(optJSON string) (options, error) {
	var opts options
	if optJSON != "" {
		if err := json.Unmarshal([]byte(optJSON), &opts); err != nil {
			return opts, err
		}
	}

	if opts.ScanMode == "" {
		opts.ScanMode = passiveScanMode
	}

	return opts, nil
}

func main() {
	c := check.NewCheckFromHandler(checkName, run)
	c.RunAndServe()
}

func run(ctx context.Context, target string, optJSON string, state state.State) error {
	if target == "" {
		return errors.New("check target missing")
	}
	api, ok := os.LookupEnv(burpEndPointEnv)
	if !ok {
		return ErrNoBurpAPIEndPoint
	}

	opts, err := buildOptions(optJSON)
	if err != nil {
		return err
	}

	c, err := resturp.New(http.DefaultClient, api, "")
	if err != nil {
		return err
	}

	// If a scan id is specified try to generete the vulns
	// from the corresponding already existent
	if opts.ScanID != 0 {
		s, err := c.GetScanStatus(opts.ScanID)
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

	configs, err := opts.ScanMode.toBurpConfigs()
	if err != nil {
		return err
	}

	id, err := c.LaunchScan(target, configs)
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
	t := time.NewTicker(3 * time.Second)
	timeout := time.NewTimer(defaultTimeout)
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
		case <-timeout.C:
			err = errors.New("timeout waiting scan to finish")
			break LOOP
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
		if i.Type != "issue_found" {
			continue
		}
		if i.Issue.Confidence == "tentative" {
			continue
		}
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
