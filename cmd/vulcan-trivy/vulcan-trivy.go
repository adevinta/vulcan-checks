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
	"path"
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

const (
	vulnCVETruncateLimit = 10
	DefaultDepth         = 1
)

var (
	checkName        = "vulcan-trivy"
	logger           = check.NewCheckLog(checkName)
	reportOutputFile = "report.json"
	localTargets     = regexp.MustCompile(`https?://(localhost|host\.docker\.internal|172\.17\.0\.1)`)
)

type options struct {
	ForceUpdateDB bool   `json:"force_update_db"`
	IgnoreUnfixed bool   `json:"ignore_unfixed"`
	Severities    string `json:"severities"`
	Depth         int    `json:"depth"`
	Branch        string `json:"branch"`
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
	Misconfigurations []struct {
		ID            string   `json:"ID"`
		Type          string   `json:"Type"`
		Title         string   `json:"Title,omitempty"`
		Description   string   `json:"Description,omitempty"`
		Message       string   `json:"Message,omitempty"`
		Resolution    string   `json:"Resolution,omitempty"`
		Severity      string   `json:"Severity"`
		References    []string `json:"References,omitempty"`
		PrimaryURL    string   `json:"PrimaryURL,omitempty"`
		CauseMetadata struct {
			StartLine int `json:"StartLine"`
			EndLine   int `json:"EndLine"`
			Code      struct {
				Lines []struct {
					Number  int    `json:"Number"`
					Content string `json:"Content"`
				}
			} `json:"Code"`
		} `json:"CauseMetadata"`
	} `json:"Misconfigurations"`
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
	title    string
}

func main() {
	c := check.NewCheckFromHandler(checkName, run)
	c.RunAndServe()
}

func run(ctx context.Context, target, assetType, optJSON string, state checkstate.State) error {
	// TODO: If options are "malformed" perhaps we should not return error
	// but only log and error and return.
	var opt options
	if optJSON != "" {
		if err := json.Unmarshal([]byte(optJSON), &opt); err != nil {
			return err
		}
	}

	trivyArgs := []string{}
	// Skip vulnerability db update if not explicitly forced.
	if !opt.ForceUpdateDB {
		trivyArgs = append(trivyArgs, "--skip-update")
	}
	// Show only vulnerabilities with fixes.
	if opt.IgnoreUnfixed {
		trivyArgs = append(trivyArgs, "--ignore-unfixed")
	}
	// Restrict to vulnerabilities (no config/secrets yet)
	trivyArgs = append(trivyArgs, "--security-checks", "vuln")

	if strings.Contains(assetType, "DockerImage") {
		// Load required env vars for docker registry authentication.
		registryEnvDomain := os.Getenv("REGISTRY_DOMAIN")
		registryEnvUsername := os.Getenv("REGISTRY_USERNAME")
		registryEnvPassword := os.Getenv("REGISTRY_PASSWORD")

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

		results, err := execTrivy(opt, "image", append(trivyArgs, target))
		if err != nil {
			return err
		}

		vuln := report.Vulnerability{
			// Issue attributes.
			Summary:     "Outdated Packages in Docker Image",
			Description: "Vulnerabilities have been found in outdated packages installed in the Docker image.",
			Recommendations: []string{
				"Update affected packages to the versions specified in the resources table or newer.",
			},
			Details: strings.Join([]string{
				"Run the following command to obtain the full report in your computer.",
				"If using a public docker registry:",
				fmt.Sprintf(`docker run -it --rm aquasec/trivy image %s`, target),
				"\n",
				"If using a private docker registry:",
				fmt.Sprintf(`docker run -it --rm \
				-e TRIVY_AUTH_URL=https://%s \
				-e TRIVY_USERNAME=$REGISTRY_USERNAME \
				-e TRIVY_PASSWORD=$REGISTRY_PASSWORD \
				aquasec/trivy image %s`, registryEnvDomain, target),
			}, "\n"),
			CWEID:  937,
			Labels: []string{"potential", "docker"},
			// Finding attributes.
		}
		return processVulns(results.Results, vuln, state)

	} else if assetType == "GitRepository" {
		if opt.Depth == 0 {
			opt.Depth = DefaultDepth
		}
		// TODO: use branch
		repoPath, branchName, err := helpers.CloneGitRepository(target, opt.Branch, opt.Depth)
		if err != nil {
			return err
		}
		results, err := execTrivy(opt, "fs", append(trivyArgs, repoPath))
		if err != nil {
			logger.Errorf("Can not execute trivy: %+v", err)
		} else {
			vuln := report.Vulnerability{
				// Issue attributes.
				Summary:     "Outdated Packages in Git Repository",
				Description: "Vulnerabilities have been found in outdated packages referenced in Git Repository.",
				Recommendations: []string{
					"Update affected packages to the versions specified in the resources table or newer.",
				},
				Details: strings.Join([]string{
					"Run the following command to obtain the full report in your computer.",
					"If using a public git repository:",
					fmt.Sprintf("\tdocker run -it --rm aquasec/trivy repository %s", target),
					"If using a private repository clone first:",
					fmt.Sprintf("\tgit clone %s repo", target),
					"\tdocker run -it -v $PWD/repo:/repo --rm aquasec/trivy fs /repo",
				}, "\n"),
				CWEID:  937,
				Labels: []string{"potential", "git"},
				// Finding attributes.
			}
			if err := processVulns(results.Results, vuln, state); err != nil {
				logger.Errorf("processing fs results: %+v", err)
			}
		}
		results, err = execTrivy(opt, "config", []string{
			"--ignorefile", path.Join(repoPath, ".trivyignore"),
			repoPath})
		if err != nil {
			return err
		}
		return processMisconfigs(results.Results, target, branchName, state)
	}
	return fmt.Errorf("Unknown assetType %s", assetType)
}

func execTrivy(opt options, action string, actionArgs []string) (*results, error) {
	// Build trivy command with arguments.
	trivyCmd := "./trivy"
	trivyArgs := []string{
		action,
		"-f", "json",
		"-o", reportOutputFile,
	}
	// Show only vulnerabilities with specific severities.
	if opt.Severities != "" {
		severitiesFlag := []string{"--severity", opt.Severities}
		trivyArgs = append(trivyArgs, severitiesFlag...)
	}
	// Append the custom params.
	trivyArgs = append(trivyArgs, actionArgs...)

	logger.Infof("running command: %s %s\n", trivyCmd, trivyArgs)

	err := retry.Do(
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
		return nil, errors.New("trivy command execution failed")
	}

	byteValue, err := ioutil.ReadFile(reportOutputFile)
	if err != nil {
		logger.Errorf("trivy report output file read failed with error: %s\n", err)
		return nil, errors.New("trivy report output file read failed")
	}

	var results results
	err = json.Unmarshal(byteValue, &results)
	if err != nil {
		return nil, errors.New("unmarshal trivy output failed")
	}
	return &results, nil
}

func processMisconfigs(results scanResponse, target string, branch string, state checkstate.State) error {

	m := map[string]report.Vulnerability{}
	for _, tt := range results {
		for _, tv := range tt.Misconfigurations {

			summary := fmt.Sprintf("%s - %s", tv.Type, tv.Title)
			key := fmt.Sprintf("%s|%s", summary, tt.Target)

			vuln, ok := m[key]
			if !ok {
				vuln = report.Vulnerability{
					Details: strings.Join([]string{
						"Run the following command to obtain the full report in your computer.",
						"Clone your repo and execute:",
						fmt.Sprintf("\tgit clone %s repo", target),
						"\tdocker run -it -v $PWD/repo:/repo --rm aquasec/trivy config --ignorefile /repo/.trivyignore /repo",
						fmt.Sprintf("If you want to ignore this findings you can add %s to a .trivyignore file in your repo", tv.ID),
					}, "\n"),
					// CWEID:  937,
					Labels:           []string{"potential", "config", "trivy"},
					Summary:          summary,
					Description:      tv.Description,
					Recommendations:  []string{tv.Resolution},
					References:       tv.References,
					Score:            getScore(tv.Severity),
					AffectedResource: computeAffectedResource(target, branch, tt.Target, 1),
					Resources: []report.ResourcesGroup{{
						Name: "Found in",
					},
					}}
				m[key] = vuln
			}
			var sb strings.Builder
			for _, l := range tv.CauseMetadata.Code.Lines {
				sb.WriteString(l.Content + "\n")
			}

			// Store the fingerprint of the contents separated with | for later split and sort.
			vuln.Fingerprint += fmt.Sprintf("%s|", helpers.ComputeFingerprint(sb.String()))

			vuln.Resources[0].Rows = append(vuln.Resources[0].Rows,
				map[string]string{
					"Message": tv.Message,
					"Link":    computeAffectedResource(target, branch, tt.Target, tv.CauseMetadata.StartLine),
				})
		}
	}

	// Compress the resource table by removing columns with the same value and adding it to Details
	fields := []string{
		"Message",
		"Link",
	}
	for _, v := range m {
		v.Fingerprint = helpers.ComputeFingerprint(sort.StringSlice(strings.Split(v.Fingerprint, "|")))

		var reduce strings.Builder

		for _, field := range fields {
			same := true
			value := ""
			for i, row := range v.Resources[0].Rows {
				if i == 0 {
					value = row[field]
				}
				if same && (row[field] != value) {
					same = false
				}
			}
			if same {
				if value != "" {
					reduce.WriteString(fmt.Sprintf("%s: %s\n", field, value))
				}
				for _, row := range v.Resources[0].Rows {
					delete(row, field)
				}
			} else {
				v.Resources[0].Header = append(v.Resources[0].Header, field)
			}
		}
		if reduce.Len() > 0 {
			v.Details = fmt.Sprintf("%s\n%s", reduce.String(), v.Details)
		}
		if len(v.Resources[0].Header) == 0 {
			v.Resources = nil
		}
		v.Fingerprint = helpers.ComputeFingerprint(v.Fingerprint)
		state.AddVulnerabilities(v)
	}

	return nil
}

func computeAffectedResource(target, branch string, file string, l int) string {
	if localTargets.MatchString(target) {
		return fmt.Sprintf("%s#%d", strings.TrimPrefix(file, "/"), l)
	}
	return helpers.GenerateGithubURL(target, branch, file, l)
}

func processVulns(results scanResponse, vuln report.Vulnerability, state checkstate.State) error {
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
				title:    tv.Title,
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
			"Title",
		},
	}

	for key, det := range outdatedPackageVulns {
		l := det.packages

		// Sort CVEs by severity desc, cve desc
		sort.Slice(l, func(i, j int) bool {
			if l[i].severity == l[j].severity {
				return cve2num(l[i].cve) > cve2num(l[j].cve)
			}
			return getScore(l[i].severity) > getScore(l[j].severity)
		})

		vp.Rows = []map[string]string{}
		maxScore := getScore("NONE")
		fingerprint := []string{}
		for i, p := range l {
			fingerprint = append(fingerprint, p.cve+p.severity)

			// Compute the fingerprint for all the CVEs but add only vulnCVETruncateLimit to the table
			if i >= vulnCVETruncateLimit {
				continue
			}

			newScore := getScore(p.severity)
			if newScore > maxScore {
				maxScore = newScore
			}
			row := map[string]string{}
			row["Fixed Version"] = p.fixedBy
			if p.cwes != nil {
				urls := []string{}
				for _, cwe := range p.cwes {
					urls = append(urls, fmt.Sprintf("[%s](https://cwe.mitre.org/data/definitions/%s.html)", cwe, strings.TrimPrefix(cwe, "CWE-")))
				}
				row["CWEs"] = strings.Join(urls, ", ")
			}
			if p.link == "" {
				row["Vulnerabilities"] = p.cve
			} else {
				row["Vulnerabilities"] = fmt.Sprintf("[%s](%s)", p.cve, p.link)
			}
			row["Severity"] = p.severity
			row["Title"] = p.title
			vp.Rows = append(vp.Rows, row)
		}

		// Ensure the order is not relevant.
		sort.Strings(fingerprint)

		vuln.AffectedResource = strings.TrimSpace(fmt.Sprintf("%s:%s", key.name, key.version))
		vuln.Fingerprint = helpers.ComputeFingerprint(key.path, fingerprint)
		vuln.Score = maxScore
		vuln.Resources = []report.ResourcesGroup{
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
		}

		// Build the vulnerability.
		state.AddVulnerabilities(vuln)
	}

	return nil
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

var cveRegex = regexp.MustCompile(`^CVE-(\d{4})-(\d+)$`)

// cve2num returns a numeric representation with year and id in case of CVE or a 0 otherwise
func cve2num(cve string) int {
	m := cveRegex.FindStringSubmatch(cve)
	if len(m) == 3 {
		year, _ := strconv.Atoi(m[1])
		id, _ := strconv.Atoi(m[2])
		return year*1000000 + id
	}
	return 0
}
