package main

import (
	"context"
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
	"github.com/adevinta/vulcan-check-sdk/state"
	"github.com/avast/retry-go"
	"github.com/mcuadros/go-version"
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

var vuln = report.Vulnerability{
	Summary:     "Outdated Packages in Docker Image (BETA)",
	Description: "Vulnerabilities have been found in outdated packages installed in the Docker image.",
	CWEID:       937,
	Recommendations: []string{
		"Update affected packages to the versions specified in the resources table or newer.",
	},
}

func main() {
	c := check.NewCheckFromHandler(checkName, run)
	c.RunAndServe()
}

func run(ctx context.Context, target, targetType string, optJSON string, state state.State) error {
	var reportTruncated bool
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

	err := retry.Do(
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
	if len(results) < 1 {
		return nil
	}

	ap := report.ResourcesGroup{
		Name: "Affected Packages",
		Header: []string{
			"Name",
			"Version",
			"Severity",
			"FixedBy",
		},
	}

	vp := report.ResourcesGroup{
		Name: "Package Vulnerabilities",
		Header: []string{
			"Name",
			"Version",
			"Vulnerabilities",
		},
	}

	var rows []map[string]string
	duppedPackageVulns := make(map[string]map[string]string)

	for _, trivyTarget := range results {
		for _, dockerVuln := range trivyTarget.Vulnerabilities {
			// Set global score for the report.
			score := getScore(dockerVuln.Severity)
			if score > vuln.Score {
				vuln.Score = score
			}

			ap := map[string]string{
				"Name":            dockerVuln.PkgName,
				"Version":         dockerVuln.InstalledVersion,
				"Severity":        dockerVuln.Severity,
				"FixedBy":         dockerVuln.FixedVersion,
				"Vulnerabilities": fmt.Sprintf("[%s](https://nvd.nist.gov/vuln/detail/%s)", dockerVuln.VulnerabilityID, dockerVuln.VulnerabilityID),
			}

			// Check if affected package has already been indexed.
			key, ok := duppedPackageVulns[ap["Name"]]
			if !ok {
				duppedPackageVulns[ap["Name"]] = ap
				continue
			}

			// Append VulnerabilityID to the affected package vulnerabilities.
			// Truncate Vulnerabilities to 10 to avoid overflow the report.
			switch count := len(strings.Split(key["Vulnerabilities"], "|")); {
			case count < 10:
				key["Vulnerabilities"] = fmt.Sprintf("%s | %s", key["Vulnerabilities"], ap["Vulnerabilities"])
			case count == 10:
				key["Vulnerabilities"] = fmt.Sprintf("%s | and some others ...", key["Vulnerabilities"])
				reportTruncated = true
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

	// To avoid report size overflow only top 30 vulnerabilities are shown.
	// In addition, docker commands are provided to let the user generate
	// the full report.
	totalVulnerablePackages := len(rows)
	if totalVulnerablePackages > 30 {
		logger.Warn("truncate to top 30 vulnerabilities\n")
		reportTruncated = true
		rows = rows[0:30]
	}

	if reportTruncated {
		vuln.Details = generateDetails(len(rows), totalVulnerablePackages, registryEnvDomain, target)
	}

	ap.Rows = rows
	vp.Rows = rows

	vuln.Resources = append(vuln.Resources, ap, vp)
	state.AddVulnerabilities(vuln)

	return nil
}

func generateDetails(vp, totalVP int, registry, target string) string {
	details := []string{
		fmt.Sprintf("This report shows %d vulnerable packages out of %d.", vp, totalVP),
		"Some vulnerability description might have been truncated.",
		"Run the following command to obtain the full report.",
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
