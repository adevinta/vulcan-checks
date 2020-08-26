package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
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

	defaultTimeout = 30 * time.Minute
)

type options struct {
	ScanMode ScanMode `json:"vulcan_burp.scan_mode"`
}

// ScanMode possible scan modes are: "active" and "passive".
type ScanMode string

func (s ScanMode) toBurpConfigs() ([]string, error) {
	if s == "passive" || s == "" {
		return []string{"Crawl limit - 10 minutes", "Audit checks - passive"}, nil
		// return []string{"CustomCrawling4", "Audit checks - passive"}, nil
	}

	if s == "active" {
		return []string{"Crawl limit - 10 minutes", "Audit coverage - maximum"}, nil
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
	configs, err := opts.ScanMode.toBurpConfigs()
	if err != nil {
		return err
	}
	c, err := resturp.New(http.DefaultClient, api, "")
	if err != nil {
		return err
	}
	fmt.Printf("configs %+s\n", configs)
	id, err := c.LaunchScan(target, configs)
	if err != nil {
		return err
	}
	s, err := waitScanFinished(id, c)
	if err != nil {
		return err
	}
	vulns := fillVulns(s.IssueEvents)
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
			break
		}
	}
	return s, err
}

func fillVulns(ievents []resturp.IssueEvent) []report.Vulnerability {
	var vulns []report.Vulnerability
	for _, i := range ievents {
		if i.Type != "issue_found" {
			continue
		}
		if i.Issue.Confidence == "Tentative" {
			continue
		}
		v := fillVuln(i.Issue)
		vulns = append(vulns, v)
	}
	return vulns
}

func fillVuln(i resturp.Issue) report.Vulnerability {
	v := report.Vulnerability{}
	v.Summary = i.Name
	v.Description = i.Description
	v.Details = i.InternalData

	// TODO get issue info from  curl -vgw "\n" -X GET
	// 'http://localhost:1337/api/v0.1/knowledge_base/issue_definitions' buy
	// using the field type_index to index the issue_type_id.
	// v.Recommendations = strings.Split(recommendations, "\n")
	// references, ok := a["reference"].(string)
	// v.References = strings.Split(references, "\n")
	// v.CWEID = uint32(cweIDInt)

	v.Score = severityToScore(i.Severity)
	path := i.Path
	// TODO fill evidences an other informations.
	v.Resources = []report.ResourcesGroup{
		report.ResourcesGroup{
			Name: "Paths",
			Header: []string{
				"Path",
			},
			Rows: []map[string]string{
				map[string]string{
					"Path": path,
				},
			},
		},
	}
	return v
}

func severityToScore(risk string) float32 {
	switch risk {
	case "info":
		return float32(report.SeverityNone)
	case "low":
		return float32(report.SeverityLow)
	case "medium":
		return float32(report.SeverityMedium)
	case "high":
		return float32(report.SeverityHigh)
	}

	return float32(report.SeverityNone)
}
