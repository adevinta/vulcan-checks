package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jpillora/backoff"
	log "github.com/sirupsen/logrus"

	"github.com/adevinta/restuss"
	"github.com/adevinta/vulcan-check-sdk/helpers"
	checkstate "github.com/adevinta/vulcan-check-sdk/state"
	report "github.com/adevinta/vulcan-report"
)

const (
	// Default polling interval is 5min.
	defPollingInterval = 5 * 60
	// Default delay range is 1min.
	defDelayRange = 60
)

// Runner executes a Nessus check.
type Runner interface {
	Run(ctx context.Context) (err error)
}

type runner struct {
	nessusCli           *restuss.NessusClient
	nessusPersistedScan *restuss.PersistedScan
	Delete              bool
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

	p, err := strconv.Atoi(os.Getenv("NESSUS_POLICY_ID"))
	if err != nil {
		return fmt.Errorf("wrong value for NESSUS_POLICY_ID: %v", err)
	}
	policyID := int64(p)

	basicAuth := opt.BasicAuth

	// Default value for delete option is TRUE
	r.Delete = true
	if opt.Delete != nil {
		r.Delete = *opt.Delete
	}

	pollingInterval := opt.PollingInterval
	if pollingInterval <= 0 {
		pollingInterval = defPollingInterval
	}

	// In order to not overload Tenable API
	// sleep a random time from within a range
	// so we distribute initial spike during
	// scans creation process.
	delayRange := opt.DelayRange
	if delayRange <= 0 {
		delayRange = defDelayRange
	}
	delay := time.Duration(rand.Intn(delayRange)) * time.Second
	logger.Infof("Delaying startup for %v", delay)
	time.Sleep(delay)

	logger = logger.WithFields(log.Fields{
		"target":    target,
		"policy ID": policyID,
	})
	err = r.auth(basicAuth)
	if err != nil {
		return err
	}
	policy, err := r.loadPolicyDetails(ctx, policyID)
	if err != nil {
		return err
	}
	scan, err := r.launchScan(ctx, target, policy)
	if err != nil {
		return err
	}
	// We need to store in a field the scan info in order to delete it in the clean
	// up step.
	r.nessusPersistedScan = scan
	scanDetail, err := r.waitUntilScanFinishes(ctx, pollingInterval)
	if err != nil {
		return err
	}
	vulns, err := r.addVulnerabilities(*scanDetail, target)
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

func (r *runner) loadPolicyDetails(ctx context.Context, policyID int64) (restuss.Policy, error) {
	policyDetails, err := r.nessusCli.GetPolicyByIDContext(ctx, policyID)
	if err != nil {
		return restuss.Policy{}, fmt.Errorf("error loading policy: %+v", err)
	}
	if policyDetails == nil {
		return restuss.Policy{}, errors.New("Returned policy is nil")
	}
	return *policyDetails, nil
}

func (r *runner) launchScan(ctx context.Context, target string, policy restuss.Policy) (*restuss.PersistedScan, error) {
	scan, err := r.nessusCli.CreateScanContext(ctx,
		&restuss.Scan{
			TemplateUUID: policy.UUID,
			Settings: restuss.ScanSettings{
				Enabled:  true,
				Name:     policy.Settings.Name + ": " + target,
				Targets:  target,
				PolicyID: policy.ID,
			}})
	if err != nil {
		return nil, err
	}
	logger := logger.WithFields(log.Fields{
		"scan": fmt.Sprintf("%+v", scan),
	})
	logger.Debug("Scan Created")

	b := &backoff.Backoff{
		Min:    100 * time.Millisecond,
		Max:    60 * time.Second,
		Factor: 1.5,
		Jitter: true,
	}

	rand.Seed(time.Now().UnixNano())

	// Try 20 times then return an error
	for i := 0; i < 20; i++ {
		err = r.nessusCli.LaunchScan(scan.ID)
		if err == nil {
			return scan, nil
		}

		d := b.Duration()
		logger.Debug(fmt.Sprintf("Err when launching scan: %v, trying again in %v", err, d))
		time.Sleep(d)
	}

	return nil, fmt.Errorf("Not possible to launch scan: %v", scan.ID)

}

func (r *runner) deleteScan(ctx context.Context, scanID int64) error {
	err := r.nessusCli.DeleteScanContext(ctx, scanID)
	if err != nil {
		logger.WithFields(log.Fields{
			"scan": fmt.Sprintf("%+v", r.nessusPersistedScan), "error": err,
		}).Error("error deleting Nessus scan")
		return err
	}

	logger.WithFields(log.Fields{
		"scan": fmt.Sprintf("%+v", r.nessusPersistedScan),
	}).Debug("Scan deleted from Nessus")

	return err
}

func (r *runner) waitUntilScanFinishes(ctx context.Context, pollingInterval int) (*restuss.ScanDetail, error) {
	t := time.NewTicker(time.Duration(pollingInterval) * time.Second)
LOOP:
	for {
		select {
		case <-ctx.Done():
			logger.Infof("ctx.Done")
			t.Stop()
			return nil, ctx.Err()
		case <-t.C:
			scanDetail, err := r.nessusCli.GetScanByID(r.nessusPersistedScan.ID)
			if err != nil {
				logger.WithFields(log.Fields{
					"scan": fmt.Sprintf("%+v", r.nessusPersistedScan),
				}).Errorf("Error while retrieving scan details: %v", err)
				continue LOOP
			}
			if scanDetail == nil {
				logger.WithFields(log.Fields{
					"scan": fmt.Sprintf("%+v", r.nessusPersistedScan),
				}).Errorf("Missing Status information when retrieving Nessus scan information. will try again in 30 seconds.")
				continue LOOP
			}
			logger.WithFields(log.Fields{
				"nessusScanID": fmt.Sprintf("%+v", r.nessusPersistedScan.ID),
			}).Infof("Status: %s", scanDetail.Info.Status)

			if scanDetail.Info.Status == "completed" {
				t.Stop()
				return scanDetail, nil
			}

			if scanDetail.Info.Status == "canceled" {
				t.Stop()
				return nil, errors.New("canceled")
			}

			if scanDetail.Info.Status == "aborted" {
				t.Stop()
				return nil, errors.New("aborted")
			}
		}
	}
}

// CleanUp is called by the sdk when the check needs to be aborted in order to give the
// opportunity to clean up resources.
func (r *runner) CleanUp(ctx context.Context, target, assetType, opts string) {
	l := logger.WithFields(log.Fields{"action": "CleanUp"})
	l.Debug("cleaning up nessus scan")
	if r.nessusPersistedScan == nil {
		l.Debug("no clean up needed")
		return
	}
	id := r.nessusPersistedScan.ID
	// Get the last status of the scan.
	scanDetail, err := r.nessusCli.GetScanByIDContext(ctx, r.nessusPersistedScan.ID)
	if err != nil {
		l.Errorf("error cleaning scan %+v", r.nessusPersistedScan)
		return
	}
	if !(scanDetail.Info.Status == "canceled") && !(scanDetail.Info.Status == "completed") {
		l.Debug("stopping scan")
		err = r.nessusCli.StopScanContext(ctx, id)
		if err != nil {
			l.WithError(err).Errorf("error trying to stop the scan")
			return
		}
		// We decrease the pool time here because stoping a scan should take far less time
		// than running a scan.
		_, err = r.waitUntilScanFinishes(ctx, 2)
		if err != nil && err.Error() != "canceled" {
			l.WithError(err).Errorf("error while waiting the scan to stop")
			return
		}
	}

	if r.Delete {
		err = r.deleteScan(ctx, id)
		if err != nil {
			l.WithError(err).Error("error deleting scan")
		}
	}
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
		vulcanVulnerability, err := r.translateFromNessusToVulcan(hostID, target, nessusVulnerability)
		if err != nil {
			logger.Errorf("Error reading nessusVulnerability[%v] :%v", nessusVulnerability.PluginName, err)
			continue
		}
		vulns = append(vulns, *vulcanVulnerability)
	}
	return vulns, nil
}

func (r *runner) translateFromNessusToVulcan(hostID int64, target string, nessusVulnerability restuss.Vulnerability) (*report.Vulnerability, error) {
	vulcanVulnerability := &report.Vulnerability{}
	p, err := r.nessusCli.GetPluginByID(nessusVulnerability.PluginID)
	if err != nil {
		return nil, err
	}

	attributesMap := make(map[string]string)
	for _, attr := range p.Attributes {
		attributesMap[attr.Name] = attr.Value
	}

	vulcanVulnerability.Summary = p.Name

	var ok bool
	var scoreString string
	scoreString, ok = attributesMap["cvss_base_score"]
	if ok {
		score, errParse := strconv.ParseFloat(scoreString, 32)
		if errParse != nil {
			return nil, errParse
		}

		vulcanVulnerability.Score = float32(score)
	} else {
		vulcanVulnerability.Score = report.ScoreSeverity(report.SeverityRank(nessusVulnerability.Severity))
	}

	if len(attributesMap["cwe"]) > 0 {
		cweid, errAtoi := strconv.Atoi(attributesMap["cwe"])
		if errAtoi != nil {
			return nil, errAtoi
		}
		vulcanVulnerability.CWEID = uint32(cweid)
	}

	vulcanVulnerability.Description = attributesMap["description"]
	vulcanVulnerability.ImpactDetails = attributesMap["synopsis"]

	if len(attributesMap["solution"]) > 0 {
		vulcanVulnerability.Recommendations = append(vulcanVulnerability.Recommendations, attributesMap["solution"])
	}

	if len(attributesMap["see_also"]) > 0 {
		references := strings.Split(attributesMap["see_also"], "\n")
		vulcanVulnerability.References = append(vulcanVulnerability.References, references...)
	}

	pluginOutput, err := r.nessusCli.GetPluginOutput(r.nessusPersistedScan.ID, hostID, nessusVulnerability.PluginID)
	if err != nil {
		return nil, err
	}

	for _, output := range pluginOutput.Output {
		vulcanVulnerability.Details = vulcanVulnerability.Details + output.Output + "\n"
	}

	gr := report.ResourcesGroup{
		Name: "Network Resources",
		Header: []string{
			"Hostname",
			"Port",
			"Protocol",
			"Service",
		},
	}
	for _, output := range pluginOutput.Output {
		mapPorts, ok := output.Ports.(map[string]interface{})
		// only parse the mapPorts if we get the right type
		if ok {
			for portInformation := range mapPorts {
				parts := strings.Split(portInformation, " / ")
				if len(parts) < 3 {
					continue
				}
				networkResource := map[string]string{
					"Hostname": target,
					"Port":     parts[0],
					"Protocol": parts[1],
					"Service":  parts[2],
				}
				gr.Rows = append(gr.Rows, networkResource)
			}
		}
	}
	if len(gr.Rows) > 0 {
		vulcanVulnerability.Resources = append(vulcanVulnerability.Resources, gr)
	}

	return vulcanVulnerability, nil
}
