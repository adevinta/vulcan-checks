/*
Copyright 2020 Adevinta
*/

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	report "github.com/adevinta/vulcan-report"
	"github.com/mcuadros/go-version"

	check "github.com/adevinta/vulcan-check-sdk"
	"github.com/adevinta/vulcan-check-sdk/helpers"
	checkstate "github.com/adevinta/vulcan-check-sdk/state"
	"github.com/avast/retry-go"
)

const vulnCVETruncateLimit = 10

var (
	checkName        = "vulcan-trivy"
	logger           = check.NewCheckLog(checkName)
	reportOutputFile = "report.json"
)

type options struct {
	ForceUpdateDB bool   `json:"force_update_db"`
	IgnoreUnfixed bool   `json:"ignore_unfixed"`
	Severities    string `json:"severities"`
}

type results struct {
	Results scanResponse `json:"Results"`
}

type scanResponse []struct {
	Target          string `json:"Target"`
	Class           string `json:"Class"`
	Type            string `json:"Type"`
	Vulnerabilities []struct {
		VulnerabilityID  string   `json:"VulnerabilityID"`
		PkgName          string   `json:"PkgName"`
		PkgPath          string   `json:"PkgPath"`
		InstalledVersion string   `json:"InstalledVersion"`
		FixedVersion     string   `json:"FixedVersion"`
		Title            string   `json:"Title,omitempty"`
		Description      string   `json:"Description,omitempty"`
		Severity         string   `json:"Severity"`
		References       []string `json:"References,omitempty"`
		PrimaryURL       string   `json:"PrimaryURL,omitempty"`
		CweIDs           []string `json:"CweIDs,omitempty"`
	} `json:"Vulnerabilities"`
}

type vulnKey struct {
	name    string
	version string
	path    string
}

type vulnData struct {
	packages []outdatedPackage
	fixedBy  string
}

type outdatedPackage struct {
	severity string
	fixedBy  string
	cve      string
	link     string
	cwes     []string
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

	slashSplit := strings.SplitAfterN(target, "/", 2)
	if len(slashSplit) <= 1 {
		logger.Warnf("%s does not have a path", target)
	}
	targetSplit := strings.Split(slashSplit[len(slashSplit)-1], ":")
	if len(targetSplit) != 2 {
		logger.Warnf("%s does not have a tag", target)
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
	trivyCmd := "./trivy"
	trivyArgs := []string{
		"image",
		"-f", "json",
		"-o", reportOutputFile,
	}
	// Skip vulnerability db update if not explicitly forced.
	if !opt.ForceUpdateDB {
		trivyArgs = append(trivyArgs, "--skip-update")
		// Log warn if skip vulnerability db update and image tag is latest.
		if strings.HasSuffix(target, "latest") {
			logger.Warnf("skipping vulnerability db update with latest tag: %s\n", target)
		}
	}

	// Show only vulnerabilities with fixes.
	if opt.IgnoreUnfixed {
		trivyArgs = append(trivyArgs, "--ignore-unfixed")
	}
	// Show only vulnerabilities with specific severities.
	if opt.Severities != "" {
		severitiesFlag := []string{"--severity", opt.Severities}
		trivyArgs = append(trivyArgs, severitiesFlag...)
	}
	// Restrict to vulnerabilities (no config/secrets yet)
	trivyArgs = append(trivyArgs, "--security-checks", "vuln")
	// Append the target (docker image including registry hostname).
	trivyArgs = append(trivyArgs, target)

	logger.Infof("running command: %s %s\n", trivyCmd, trivyArgs)

	err = retry.Do(
		func() error {
			cmd := exec.Command(trivyCmd, trivyArgs...)
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

	var results results
	err = json.Unmarshal(byteValue, &results)
	if err != nil {
		return errors.New("unmarshal trivy output failed")
	}

	return processVulns(results.Results, registryEnvDomain, target, state)
}

func processVulns(results scanResponse, registryEnvDomain, target string, state checkstate.State) error {
	outdatedPackageVulns := make(map[vulnKey]*vulnData)
	for _, tt := range results {
		for _, tv := range tt.Vulnerabilities {
			path := ""
			switch {
			case tt.Class == "os-pkgs":
				// Type contains the os distro name (i.e. alpine, centos, amazon, ...)
				path = fmt.Sprintf("%s:%s", tt.Type, tv.PkgName)
			case tv.PkgPath != "":
				path = tv.PkgPath
			default:
				path = tt.Target
			}

			key := vulnKey{
				name:    tv.PkgName,
				version: tv.InstalledVersion,
				path:    path,
			}

			pkg := outdatedPackage{
				severity: tv.Severity,
				fixedBy:  tv.FixedVersion,
				cve:      tv.VulnerabilityID,
				link:     tv.PrimaryURL,
				cwes:     tv.CweIDs,
			}

			if det, ok := outdatedPackageVulns[key]; ok {
				det.packages = append(det.packages, pkg)
				if version.Compare(version.Normalize(tv.FixedVersion), version.Normalize(det.fixedBy), ">") {
					det.fixedBy = tv.FixedVersion
				}
			} else {
				det = &vulnData{
					packages: []outdatedPackage{pkg},
					fixedBy:  tv.FixedVersion,
				}
				outdatedPackageVulns[key] = det
			}
		}
	}
	vp := report.ResourcesGroup{
		Name: "Package Vulnerabilities",
		Header: []string{
			"Fixed Version",
			"Vulnerabilities",
			"Severity",
			"CWEs",
		},
	}

	for key, det := range outdatedPackageVulns {
		l := det.packages

		// Sort CVEs by severity
		sort.Slice(l, func(i, j int) bool {
			if l[i].severity == l[j].severity {
				return cve2num(l[i].cve) > cve2num(l[j].cve)
			}
			return getScore(l[i].severity) > getScore(l[j].severity)
		})

		vp.Rows = []map[string]string{}
		maxScore := getScore("NONE")
		fingerprint := make([]string, len(l))
		for i, p := range l {
			fingerprint = append(fingerprint, p.cve+p.severity)
			// Compute the fingerprint for all the CVEs but add only vulnCVETruncateLimit to the table
			if i > vulnCVETruncateLimit {
				continue
			}
			newScore := getScore(p.severity)
			if newScore > maxScore {
				maxScore = newScore
			}
			row := make(map[string]string, len(vp.Header))
			row["Fixed Version"] = p.fixedBy
			if p.cwes != nil {
				urls := []string{}
				for _, cwe := range p.cwes {
					urls = append(urls, fmt.Sprintf("[%s](https://cwe.mitre.org/data/definitions/%s.html)", cwe, strings.TrimPrefix(cwe, "CWE-")))
				}
				row["CWEs"] = strings.Join(urls, ", ")
			}
			if p.link == "" {
				p.link = fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", p.cve)
			}
			row["Vulnerabilities"] = fmt.Sprintf("[%s](%s)", p.cve, p.link)
			row["Severity"] = p.severity
			vp.Rows = append(vp.Rows, row)
		}

		// Build the vulnerability.
		state.AddVulnerabilities(report.Vulnerability{
			// Issue attributes.
			AffectedResource: strings.TrimSpace(fmt.Sprintf("%s:%s", key.name, key.version)),
			Fingerprint:      helpers.ComputeFingerprint(key.path, fingerprint),
			Summary:          "Outdated Packages in Docker Image",
			Description:      "Vulnerabilities have been found in outdated packages installed in the Docker image.",
			Recommendations: []string{
				"Update affected packages to the versions specified in the resources table or newer.",
			},
			CWEID:  937,
			Labels: []string{"potential", "docker"},
			// Finding attributes.
			Score:   maxScore,
			Details: generateDetails(registryEnvDomain, target),
			Resources: []report.ResourcesGroup{
				{
					Name: "Package",
					Header: []string{
						"Package",
						"Min. Recommended Version",
					},
					Rows: []map[string]string{{
						"Package":                  key.path,
						"Min. Recommended Version": det.fixedBy,
					}},
				},
				vp,
			},
		})
	}

	return nil
}

func generateDetails(registry, target string) string {
	details := []string{
		"Run the following command to obtain the full report in your computer.",
		"If using a public docker registry:",
		fmt.Sprintf(`
	docker run -it --rm aquasec/trivy image %s`, target,
		),
		"\n",
		"If using a private docker registry:",
		fmt.Sprintf(`
	docker run -it --rm \
		-e TRIVY_AUTH_URL=https://%s \
		-e TRIVY_USERNAME=$REGISTRY_USERNAME \
		-e TRIVY_PASSWORD=$REGISTRY_PASSWORD \
		aquasec/trivy image %s`, registry, target,
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

var CVERegex = regexp.MustCompile(`^CVE-(\d{4})-(\d+)$`)

func cve2num(cve string) int {
	m := CVERegex.FindStringSubmatch(cve)
	if len(m) == 3 {
		year, _ := strconv.Atoi(m[1])
		id, _ := strconv.Atoi(m[2])
		return year*1000000 + id
	}
	return 0
}
