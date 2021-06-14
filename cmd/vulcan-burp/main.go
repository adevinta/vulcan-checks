package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	check "github.com/adevinta/vulcan-check-sdk"
	"github.com/adevinta/vulcan-check-sdk/helpers"
	"github.com/adevinta/vulcan-check-sdk/state"
	checkstate "github.com/adevinta/vulcan-check-sdk/state"
	"github.com/adevinta/vulcan-checks/cmd/vulcan-burp/resturp"
	report "github.com/adevinta/vulcan-report"
)

const (
	activeScanMode     = "active"
	passiveScanMode    = "passive"
	burpAPIEndpointEnv = "BURP_API_ENDPOINT"
	burpUsernameEnv    = "BURP_USERNAME"
	burpPasswordEnv    = "BURP_PASSWORD"
	burpCrawlConfigEnv = "BURP_CRAWL_CONFIG"
	burpCheckConfigEnv = "BURP_CHECK_CONFIG"
)

var (
	checkName = "vulcan-burp"

	// ErrNoBurpAPIEndPoint is returned by the check when the burp api url is
	// not defined.
	ErrNoBurpAPIEndPoint = errors.New("BURP_API_ENDPOINT env var must be set")

	// ErrNoBurpCrawlConfig defines the error returned by the check when no
	// config for the crawler has been defined.
	ErrNoBurpCrawlConfig = errors.New("BURP_CRAWL_CONFIG env var must be set")

	// ErrNoBurpCheckConfig defines the error returned by the check when no
	// config for the checks has been defined.
	ErrNoBurpCheckConfig = errors.New("BURP_CHECK_CONFIG env var must be set")

	// ErrInvalidScanMode is returned when an invalid scan mode was specified.
	ErrInvalidScanMode = errors.New("invalid scan mode")

	defaultTimeout = 500 * time.Minute
)

// Options defines the possible options to be received by the check.
type Options struct {
	ScanID uint `json:"scan_id"`
}

func main() {
	c := check.NewCheckFromHandler(checkName, run)
	c.RunAndServe()
}

func run(ctx context.Context, assetType string, target string, optJSON string, state state.State) error {
	if target == "" {
		return errors.New("check target missing")
	}
	logger := check.NewCheckLog(checkName)
	logger = logger.WithFields(logrus.Fields{"target": target, "assetType": assetType})
	isReachable, err := helpers.IsReachable(target, assetType, nil)
	if err != nil {
		logger.Warnf("Can not check asset reachability: %v", err)
	}
	if !isReachable {
		return checkstate.ErrAssetUnreachable
	}

	var opt Options
	if optJSON != "" {
		if err = json.Unmarshal([]byte(optJSON), &opt); err != nil {
			return err
		}
	}

	api, ok := os.LookupEnv(burpAPIEndpointEnv)
	if !ok {
		return ErrNoBurpAPIEndPoint
	}

	crawlConfig, ok := os.LookupEnv(burpCrawlConfigEnv)
	if !ok {
		return ErrNoBurpCrawlConfig
	}

	checkConfig, ok := os.LookupEnv(burpCheckConfigEnv)
	if !ok {
		return ErrNoBurpCheckConfig
	}

	username, ok := os.LookupEnv(burpUsernameEnv)
	password, ok := os.LookupEnv(burpPasswordEnv)

	c, err := resturp.New(http.DefaultClient, api, "")
	if err != nil {
		return err
	}

	// If a scan id is specified try to generete the vulns from the
	// corresponding already existent scan, this is not intended to be used
	// running in production, only to run the check locally.
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

	configs := []string{crawlConfig, checkConfig}
	logger.Infof("scanning with policy %+v", configs)

	id, err := c.LaunchScan(target, configs, username, password)
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
	t := time.NewTicker(5 * time.Minute)
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
