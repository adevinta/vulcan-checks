/*
Copyright 2020 Adevinta
*/

package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	report "github.com/adevinta/vulcan-report"

	check "github.com/adevinta/vulcan-check-sdk"
	"github.com/adevinta/vulcan-check-sdk/helpers"
	checkstate "github.com/adevinta/vulcan-check-sdk/state"
	"github.com/avast/retry-go"
	"github.com/mcuadros/go-version"
)

const (
	vulnTruncateLimit   = 30
	vulnCVETrucateLimit = 10
)

var (
	checkName        = "vulcan-trivy"
	logger           = check.NewCheckLog(checkName)
	trivyCachePath   = "trivy_cache"
	reportOutputFile = "report.json"
)

type options struct {
	ForceUpdateDB bool   `json:"force_update_db"`
	IgnoreUnfixed bool   `json:"ignore_unfixed"`
	Severities    string `json:"severities"`
}

type ScanResponse []struct {
	Target          string `json:"Target"`
	Vulnerabilities []struct {
		VulnerabilityID  string   `json:"VulnerabilityID"`
		PkgName          string   `json:"PkgName"`
		InstalledVersion string   `json:"InstalledVersion"`
		FixedVersion     string   `json:"FixedVersion"`
		Title            string   `json:"Title,omitempty"`
		Description      string   `json:"Description,omitempty"`
		Severity         string   `json:"Severity"`
		References       []string `json:"References,omitempty"`
	} `json:"Vulnerabilities"`
}

type outdatedPackage struct {
	name     string
	version  string
	severity string
	fixedBy  string
}

type vulnerability struct {
	name     string
	severity string
	link     string
}

func main() {
	c := check.NewCheckFromHandler(checkName, run)
	c.RunAndServe()
}

func run(ctx context.Context, target, assetType, optJSON string, state checkstate.State) error {
	// Load required env vars for docker registry authentication.
	registryEnvDomain := os.Getenv("REGISTRY_DOMAIN")
	registryEnvUsername := os.Getenv("REGISTRY_USERNAME")
	registryEnvPassword := os.Getenv("REGISTRY_PASSWORD")

	// TODO: If options are "malformed" perhaps we should not return error
	// but only log and error and return.
	var opt options
	if optJSON != "" {
		if err := json.Unmarshal([]byte(optJSON), &opt); err != nil {
			return err
		}
	}

	// TODO: If target is "malformed" perhaps we should not return error
	// but only log and error and return.
	slashSplit := strings.SplitAfterN(target, "/", 2)
	if len(slashSplit) <= 1 {
		return errors.New(target + " is not a valid target")
	}
	// TODO: If target is "malformed" perhaps we should not return error
	// but only log and error and return.
	targetSplit := strings.Split(slashSplit[1], ":")
	if len(targetSplit) != 2 {
		return errors.New(target + "is not a valid target")
	}

	registryDomain := strings.Trim(slashSplit[0], "/")
	// If docker registry equals registryDomain, export trivy credential env vars.
	if registryDomain == registryEnvDomain {
		os.Setenv("TRIVY_AUTH_URL", registryEnvDomain)
		os.Setenv("TRIVY_USERNAME", registryEnvUsername)
		os.Setenv("TRIVY_PASSWORD", registryEnvPassword)
	}

	isReachable, err := helpers.IsReachable(target, assetType,
		helpers.NewDockerCreds(os.Getenv("TRIVY_USERNAME"), os.Getenv("TRIVY_PASSWORD")))
	if err != nil {
		logger.Warnf("Can not check asset reachability: %v", err)
	}
	if !isReachable {
		return checkstate.ErrAssetUnreachable
	}

	// Build trivy command with arguments.
	triviCmd := "./trivy"
	triviArgs := []string{
		"--cache-dir", trivyCachePath,
		"-f", "json",
		"-o", reportOutputFile,
	}
	// Skip vulnerability db update if not explicitly forced.
	if !opt.ForceUpdateDB {
		triviArgs = append(triviArgs, "--skip-update")
		// Log warn if skip vulnerability db update and image tag is latest.
		if strings.HasSuffix(target, "latest") {
			logger.Warnf("skipping vulnerability db update with latest tag: %s\n", target)
		}
	}

	// Show only vulnerabilities with fixes.
	if opt.IgnoreUnfixed {
		triviArgs = append(triviArgs, "--ignore-unfixed")
	}
	// Show only vulnerabilities with specific severities.
	if opt.Severities != "" {
		severitiesFlag := []string{"--severity", opt.Severities}
		triviArgs = append(triviArgs, severitiesFlag...)
	}
	// Append the target (docker image including registry hostname).
	triviArgs = append(triviArgs, target)

	logger.Infof("running command: %s %s\n", triviCmd, triviArgs)

	err = retry.Do(
		func() error {
			cmd := exec.Command(triviCmd, triviArgs...)
			cmdOutput, err := cmd.CombinedOutput()
			if err != nil {
				logger.Errorf("exec.Command() failed with %s\nCommand output: %s\n", err, string(cmdOutput))
				return errors.New("trivy command execution failed")
			}
			logger.Infof("trivy command execution completed successfully")
			return nil
		},
		retry.Attempts(3),
		retry.DelayType(retry.RandomDelay),
		retry.MaxJitter(5*time.Second),
	)
	if err != nil {
		logger.Errorf("retry exec.Command() failed with error: %s\n", err)
		return errors.New("trivy command execution failed")
	}

	byteValue, err := ioutil.ReadFile(reportOutputFile)
	if err != nil {
		logger.Errorf("trivy report output file read failed with error: %s\n", err)
		return errors.New("trivy report output file read failed")
	}

	var results ScanResponse
	err = json.Unmarshal(byteValue, &results)
	if err != nil {
		return errors.New("unmarshal trivy output failed")
	}

	// If there are no vulnerabilities we can return.
	if len(results) < 1 || len(results) == 1 && len(results[0].Vulnerabilities) == 0 {
		return nil
	}

	var rows []map[string]string
	duppedPackageVulns := make(map[string]map[string]string)
	apCVEs := make(map[string][]string)

	for _, trivyTarget := range results {
		for _, dockerVuln := range trivyTarget.Vulnerabilities {
			ap := map[string]string{
				"Name":     dockerVuln.PkgName,
				"Version":  dockerVuln.InstalledVersion,
				"Severity": dockerVuln.Severity,
				"FixedBy":  dockerVuln.FixedVersion,
			}
			apCVEs[ap["Name"]] = append(apCVEs[ap["Name"]], dockerVuln.VulnerabilityID)

			// Check if affected package has already been indexed.
			key, ok := duppedPackageVulns[ap["Name"]]
			if !ok {
				duppedPackageVulns[ap["Name"]] = ap
				continue
			}
			if isMoreSevere(ap["Severity"], key["Severity"]) {
				key["Severity"] = ap["Severity"]
			}
			if version.Compare(version.Normalize(ap["FixedBy"]), version.Normalize(key["FixedBy"]), ">") {
				key["FixedBy"] = ap["FixedBy"]
			}

			duppedPackageVulns[ap["Name"]] = key
		}
	}

	for _, v := range duppedPackageVulns {
		rows = append(rows, v)
	}

	// Sort rows by severity, alphabetical order of the package name and version.
	sort.Slice(rows, func(i, j int) bool {
		si := getScore(rows[i]["Severity"])
		sj := getScore(rows[j]["Severity"])
		switch {
		case si != sj:
			return si > sj
		case rows[i]["Name"] != rows[j]["Name"]:
			return rows[i]["Name"] < rows[j]["Name"]
		default:
			return rows[i]["Version"] < rows[j]["Version"]
		}
	})

	// To avoid report size overflow only top 30 most vulnerable packages
	// are reported.
	totalVulnerablePackages := len(rows)
	if totalVulnerablePackages > vulnTruncateLimit {
		logger.Warnf("truncate to top %d vulnerabilities\n", vulnTruncateLimit)
		rows = rows[0:vulnTruncateLimit]
	}

	// Sort apCVEs for a consistent fingerprinting.
	for _, v := range apCVEs {
		sort.Strings(v)
	}

	vp := report.ResourcesGroup{
		Name: "Package Vulnerabilities",
		Header: []string{
			"Name",
			"Version",
			"Vulnerabilities",
		},
	}

	for _, r := range rows {
		affectedResource := fmt.Sprintf("%s-%s", r["Name"], r["Version"])
		vulnerabilityID := computeVulnerabilityID(target, affectedResource, r["Severity"], apCVEs)
		description := fmt.Sprintf("Docker image package %s-%s has one or more vulnerabilities", r["Name"], r["Version"])
		cves := apCVEs[r["Name"]]
		// Build vulnerabilities Rsources table.
		vResourcesTable := make(map[string]string)
		vResourcesTable["Name"] = r["Name"]
		vResourcesTable["Version"] = r["Version"]
		for i := 0; i < len(cves) && i < vulnCVETrucateLimit; i++ {
			vResourcesTable["Vulnerabilities"] = fmt.Sprintf("%s | [%s](https://nvd.nist.gov/vuln/detail/%s)", vResourcesTable["Vulnerabilities"], cves[i], cves[i])
		}
		if len(cves) > vulnCVETrucateLimit {
			logger.Warnf("truncate affected package [%s] CVE list to [%d]\n", r["Name"], vulnCVETrucateLimit)
			vResourcesTable["Vulnerabilities"] = fmt.Sprintf("%s | and some others ...)", vResourcesTable["Vulnerabilities"])
		}
		vp.Rows = []map[string]string{vResourcesTable}
		// Build the vulnerability.
		vuln := report.Vulnerability{
			ID:               vulnerabilityID,
			AffectedResource: affectedResource,
			Summary:          "Outdated Packages in Docker Image",
			Score:            getScore(r["Severity"]),
			Description:      description,
			Details:          generateDetails(registryEnvDomain, target),
			CWEID:            937,
			Labels:           []string{"potential", "docker"},
			Recommendations: []string{
				fmt.Sprintf("Update the base docker image or [%s] package to at least version [%s]", r["Name"], r["FixedBy"]),
			},
			Resources: []report.ResourcesGroup{vp},
		}
		state.AddVulnerabilities(vuln)
	}

	return nil
}

func computeVulnerabilityID(target, affectedResource string, elems ...interface{}) string {
	h := sha256.New()

	fmt.Fprintf(h, "%s - %s", target, affectedResource)

	for _, e := range elems {
		fmt.Fprintf(h, " - %v", e)
	}

	return fmt.Sprintf("%x", h.Sum(nil))
}

func generateDetails(registry, target string) string {
	details := []string{
		"Run the following command to obtain the full report in your computer.",
		"If using a public docker registry:",
		fmt.Sprintf(`
	docker run -it --rm aquasec/trivy %s`, target,
		),
		"\n",
		"If using a private docker registry:",
		fmt.Sprintf(`
	docker run -it --rm \
		-e TRIVY_AUTH_URL=https://%s \
		-e TRIVY_USERNAME=$REGISTRY_USERNAME \
		-e TRIVY_PASSWORD=$REGISTRY_PASSWORD \
		aquasec/trivy %s`, registry, target,
		),
	}
	return strings.Join(details, "\n")
}

func getScore(severity string) float32 {
	if severity == "CRITICAL" {
		return report.SeverityThresholdCritical
	}
	if severity == "HIGH" {
		return report.SeverityThresholdHigh
	}
	if severity == "MEDIUM" {
		return report.SeverityThresholdMedium
	}
	if severity == "LOW" {
		return report.SeverityThresholdLow
	}
	return report.SeverityThresholdNone
}

func isMoreSevere(s1, s2 string) bool {
	if getScore(s1) > getScore(s2) {
		return true
	}
	return false
}
