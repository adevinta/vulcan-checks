/*
Copyright 2020 Adevinta
*/

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	report "github.com/adevinta/vulcan-report"
	"github.com/mcuadros/go-version"
	"github.com/sirupsen/logrus"

	check "github.com/adevinta/vulcan-check-sdk"
	"github.com/adevinta/vulcan-check-sdk/helpers"
	"github.com/adevinta/vulcan-check-sdk/helpers/command"
	checkstate "github.com/adevinta/vulcan-check-sdk/state"
)

const (
	vulnCVETruncateLimit = 10
	DefaultDepth         = 1
	// trivyTimeout defines the value that will be passed to the trivy CLI via
	// the '--timeout' flag. The value should be bigger than the check timeout
	// defined in the manifest, to ensure the check will have a 'TIMEOUT'
	// status when the execution takes longer than expected.
	trivyTimeout = "2h"
	// maxNonBinaryFile defines the maximum size of non binary files to be scanned for secrets.
	// Files bigger than 20MB will be skipped.
	maxNonBinaryFile = 1024 * 1024 * 20
)

var (
	checkName    = "vulcan-trivy"
	localTargets = regexp.MustCompile(`https?://(localhost|host\.docker\.internal|172\.17\.0\.1)`)

	FilePatterns = []string{
		// trivy only detect requirements.txt files
		`pip:/requirements/[^/]+\.txt`,    // All the .txt files in a requirements directory.
		`pip:[^/]*requirements[^/]*\.txt`, // All the files .txt that contains requirements
	}
	ignoredPaths = []string{
		// Paths to ignore while searching for big non binary files.
		".git", // Already ignored by trivy.
	}
)

type checks struct {
	Vuln   bool `json:"vuln"`
	Secret bool `json:"secret"`
	Config bool `json:"config"`
}

type options struct {
	ForceUpdateDB bool   `json:"force_update_db"`
	OfflineScan   bool   `json:"offline_scan"`
	IgnoreUnfixed bool   `json:"ignore_unfixed"`
	Severities    string `json:"severities"`
	Depth         int    `json:"depth"`
	Branch        string `json:"branch"`
	GitChecks     checks `json:"git_checks"`
	ImageChecks   checks `json:"image_checks"`

	DisableCustomSecretConfig bool `json:"disable_custom_secret_config"`

	// ScanImageMetadata enables scanning for secrets in the container image
	// metadata. For further information check
	// https://aquasecurity.github.io/trivy/v0.45/docs/target/container_image/
	ScanImageMetadata bool `json:"scan_image_metadata"`
}

// TODO: Replace with "github.com/aquasecurity/trivy/pkg/types"
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
				} `json:"Lines"`
			} `json:"Code"`
		} `json:"CauseMetadata"`
	} `json:"Misconfigurations"`
	Secrets []struct {
		RuleID    string `json:"RuleID"`
		Category  string `json:"Category"`
		Severity  string `json:"Severity"`
		Title     string `json:"Title"`
		StartLine int    `json:"StartLine"`
		EndLine   int    `json:"EndLine"`
		Code      struct {
			Lines []struct {
				Number  int    `json:"Number"`
				Content string `json:"Content"`
				IsCause bool   `json:"IsCause"`
			} `json:"Lines"`
			Layer struct {
				CreatedBy string `json:"CreatedBy"`
			} `json:"Layer"`
		} `json:"Code"`
	} `json:"Secrets"`
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

func checksToParam(c checks) string {
	checks := []string{}
	if c.Vuln {
		checks = append(checks, "vuln")
	}
	if c.Secret {
		checks = append(checks, "secret")
	}
	if c.Config {
		checks = append(checks, "config")
	}
	return strings.Join(checks, ",")
}

// isBinaryFile checks if a file is binary by reading the first few bytes.
// From https://github.com/aquasecurity/trivy/blob/f9fceb58bf64657dee92302df1ed97e597e474c9/pkg/fanal/utils/utils.go#L85
func isBinaryFile(path string) (bool, error) {
	file, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer file.Close()

	buf := make([]byte, 300)
	_, err = file.Read(buf)
	if err != nil {
		return false, err
	}

	for _, b := range buf {
		if b < 7 || b == 11 || (13 < b && b < 27) || (27 < b && b < 0x20) || b == 0x7f {
			return true, nil
		}
	}
	return false, nil
}

func findLargeNonBinaryFiles(rootPath string, excludeDirs []string) ([]string, error) {
	var files []string
	if !strings.HasSuffix(rootPath, "/") {
		rootPath = rootPath + "/"
	}
	err := filepath.WalkDir(rootPath, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if slices.Contains(excludeDirs, filepath.Base(path)) {
				return filepath.SkipDir
			}
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if info.Size() > maxNonBinaryFile {
			isBinary, err := isBinaryFile(path)
			if err != nil {
				return err
			}
			if !isBinary {
				files = append(files, strings.TrimPrefix(path, rootPath))
			}
		}
		return nil
	})

	return files, err
}

func run(ctx context.Context, target, assetType, optJSON string, state checkstate.State) error {
	logger := check.NewCheckLogFromContext(ctx, checkName)
	// TODO: If options are "malformed" perhaps we should not return error
	// but only log and error and return.
	var opt options
	if optJSON != "" {
		if err := json.Unmarshal([]byte(optJSON), &opt); err != nil {
			return err
		}
	}

	trivyArgs := []string{}

	// Increase the default (5m) trivy command timeout.
	trivyArgs = append(trivyArgs, []string{"--timeout", trivyTimeout}...)

	// Skip vulnerability db update if not explicitly forced.
	if !opt.ForceUpdateDB {
		trivyArgs = append(trivyArgs, "--skip-db-update", "--skip-java-db-update")
	}
	if opt.OfflineScan {
		trivyArgs = append(trivyArgs, "--offline-scan")
	}
	// Show only vulnerabilities with fixes.
	if opt.IgnoreUnfixed {
		trivyArgs = append(trivyArgs, "--ignore-unfixed")
	}

	for _, p := range FilePatterns {
		trivyArgs = append(trivyArgs, []string{"--file-patterns", fmt.Sprintf(`"%s"`, p)}...)
	}

	if strings.Contains(assetType, "DockerImage") {
		sc := checksToParam(opt.ImageChecks)
		if sc == "" {
			logger.Warnf("No checks enabled for DockerImage, falling to scan only vuln")
			sc = "vuln"
		}
		trivyArgs = append(trivyArgs, []string{"--scanners", sc}...)

		if opt.ImageChecks.Secret {
			if !opt.DisableCustomSecretConfig {
				trivyArgs = append(trivyArgs, []string{"--secret-config", "secret.yaml"}...)
			}
			if opt.ScanImageMetadata {
				trivyArgs = append(trivyArgs, []string{"--image-config-scanners", "secret"}...)
			}
		}

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

		results, err := execTrivy(ctx, logger, opt, "image", append(trivyArgs, target))
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
		processVulns(results.Results, vuln, state)

		vuln = report.Vulnerability{
			Summary:       "Secret Leaked in DockerImage",
			Description:   "A secret has been found stored in the DockerImage. This secret could be retrieved by anyone with access to the image. Test data and false positives can be marked as such.",
			CWEID:         540,
			Score:         8.9,
			ImpactDetails: "Anyone with access to the image could retrieve the leaked secret and use it in the future with malicious intent.",
			Labels:        []string{"issue"},
			Recommendations: []string{
				"Completely remove the secrets from the repository as explained in the references.",
				"Encrypt the secrets using a tool like AWS Secrets Manager or Vault.",
			},
			References: []string{
				"https://help.github.com/en/articles/removing-sensitive-data-from-a-repository",
			},
		}
		processSecrets(results.Results, vuln, target, "", state)
		processMisconfigs(results.Results, target, "", state)
		return nil
	}

	if assetType == "GitRepository" {
		sc := checksToParam(opt.GitChecks)
		if sc == "" {
			logger.Warnf("No checks enabled for GitRepository")
			return nil
		}
		trivyArgs = append(trivyArgs, []string{"--scanners", sc}...)

		// Define custom secret config when scanning secrets.
		if opt.GitChecks.Secret && !opt.DisableCustomSecretConfig {
			trivyArgs = append(trivyArgs, []string{"--secret-config", "secret.yaml"}...)
		}

		if opt.Depth == 0 {
			opt.Depth = DefaultDepth
		}
		repoPath, branchName, err := helpers.CloneGitRepositoryContext(ctx, target, opt.Branch, opt.Depth)
		if err != nil {
			logger.Errorf("unable to clone repo: %+v", err)
			return checkstate.ErrAssetUnreachable
		}
		defer os.RemoveAll(repoPath)

		// Trivy warns to --skip-files for large nonbinary (20MB) files because scanning those files for secrets can be time consuming.
		// As there is no flag to opt-in to automatically discard those files we implement it before.
		// See https://github.com/aquasecurity/trivy/blob/f9fceb58bf64657dee92302df1ed97e597e474c9/pkg/fanal/analyzer/secret/secret.go#L105
		if opt.GitChecks.Secret {
			if files, err := findLargeNonBinaryFiles(repoPath, ignoredPaths); err == nil {
				for _, f := range files {
					logger.WithField("skipped", f).Warn("Skipping large non-binary file")
					trivyArgs = append(trivyArgs, "--skip-files", f)
				}
			}
		}

		results, err := execTrivy(ctx, logger, opt, "fs", append(trivyArgs, repoPath))
		if err != nil {
			logger.Errorf("Can not execute trivy: %+v", err)
			return err
		}
		vuln := report.Vulnerability{
			// Issue attributes.
			Summary:     "Outdated Packages in Git repository",
			Description: "Vulnerabilities have been found in outdated packages referenced in Git repository.",
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
		processVulns(results.Results, vuln, state)

		vuln = report.Vulnerability{
			Summary:       "Secret Leaked In Git Repository",
			Description:   "A secret has been found stored in the Git repository. This secret may be in any historical commit and could be retrieved by anyone with read access to the repository. Test data and false positives can be marked as such.",
			CWEID:         540,
			Score:         8.9,
			ImpactDetails: "Anyone with access to the repository could retrieve the leaked secret and use it in the future with malicious intent.",
			Labels:        []string{"issue", "secret"},
			Recommendations: []string{
				"Completely remove the secrets from the repository as explained in the references.",
				"It is recommended to utilize a tool such as AWS Secrets Manager or Vault, or follow the guidance provided by your CI/CD provider, to securely store confidential information.",
			},
			References: []string{
				"https://help.github.com/en/articles/removing-sensitive-data-from-a-repository",
			},
		}
		processSecrets(results.Results, vuln, target, branchName, state)
		processMisconfigs(results.Results, target, branchName, state)
		return nil
	}

	return fmt.Errorf("unknown assetType %s", assetType)
}

func execTrivy(ctx context.Context, logger *logrus.Entry, opt options, action string, actionArgs []string) (*results, error) {
	// Build trivy command with arguments.
	trivyCmd := "trivy"
	trivyArgs := []string{
		action,
		"-f", "json",
		// Indicate Trivy CLI to output just errors to have a cleaner
		// 'check.Report.Error'.
		"--quiet",
		"--parallel", "0", // autodetect number of go routines.
	}

	// Show only vulnerabilities with specific severities.
	if opt.Severities != "" {
		severitiesFlag := []string{"--severity", opt.Severities}
		trivyArgs = append(trivyArgs, severitiesFlag...)
	}
	// Append the custom params.
	trivyArgs = append(trivyArgs, actionArgs...)

	logger.Infof("running command: %s %s\n", trivyCmd, trivyArgs)
	var results results

	exitCode, err := command.ExecuteAndParseJSON(ctx, logger, &results, trivyCmd, trivyArgs...)
	if err != nil {
		return nil, err
	}
	logger.WithFields(logrus.Fields{"exit_code": exitCode}).Debug("trivy command finished")
	return &results, nil
}

func processMisconfigs(results scanResponse, target string, branch string, state checkstate.State) error {
	m := map[string]report.Vulnerability{}
	for _, tt := range results {
		for _, tv := range tt.Misconfigurations {
			key := fmt.Sprintf("%s|%s", tv.ID, tt.Target)

			vuln, ok := m[key]
			if !ok {
				vuln = report.Vulnerability{
					Summary: fmt.Sprintf("%s - %s", tv.Type, tv.Title),
					Details: strings.Join([]string{
						"Run the following command to obtain the full report in your computer.",
						"Clone your repo and execute:",
						fmt.Sprintf("\tgit clone %s repo", target),
						"\tdocker run -it -v $PWD/repo:/repo --rm aquasec/trivy config --ignorefile /repo/.trivyignore /repo",
						fmt.Sprintf("If you want to ignore this findings you can add %s to a .trivyignore file in your repo", tv.ID),
					}, "\n"),
					// CWEID:  937,
					Labels:           []string{"potential", "config", "trivy"},
					Description:      tv.Description,
					Recommendations:  []string{tv.Resolution},
					References:       tv.References,
					Score:            getScore(tv.Severity),
					AffectedResource: computeAffectedResource(target, branch, tt.Target, 0),
					Resources: []report.ResourcesGroup{
						{
							Name:   "Occurrences",
							Header: []string{"Link", "Message"},
						},
					},
				}
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
					"Link":    computeAffectedResource(target, branch, tt.Target, tv.CauseMetadata.StartLine),
					"Message": tv.Message,
				})
		}
	}

	for _, v := range m {
		v.Fingerprint = helpers.ComputeFingerprint(sort.StringSlice(strings.Split(v.Fingerprint, "|")))

		unique := getUniqueFields(v.Resources[0])
		// Set the affectedResource with the line in case all the occurrences have the same line.
		if link, ok := unique["Link"]; ok {
			removeColumn(&v.Resources[0], "Link")
			v.AffectedResource = link
		}
		state.AddVulnerabilities(v)
	}

	return nil
}

func removeColumn(rg *report.ResourcesGroup, field string) {
	h := []string{}
	for _, f := range rg.Header {
		if f != field {
			h = append(h, f)
		}
	}

	rg.Header = h

	for _, r := range rg.Rows {
		delete(r, field)
	}
}

func getUniqueFields(rg report.ResourcesGroup) map[string]string {
	uniqueFields := map[string]string{}
	for _, field := range rg.Header {
		same := true
		value := ""
		for i, row := range rg.Rows {
			if i == 0 {
				value = row[field]
			}
			if same && (row[field] != value) {
				same = false
			}
		}
		if same {
			uniqueFields[field] = value
		}
	}
	return uniqueFields
}

func computeAffectedResource(target, branch string, file string, l int) string {
	s := ""
	if branch == "" { // it's a docker image
		s = file
	} else if localTargets.MatchString(target) {
		s = strings.TrimPrefix(file, "/")
	} else {
		s = fmt.Sprintf("%s/%s", strings.TrimSuffix(target, ".git"), path.Join("blob", branch, file))
	}
	if l == 0 {
		return s
	}
	return s + fmt.Sprintf("#L%d", l)
}

func processVulns(results scanResponse, vuln report.Vulnerability, state checkstate.State) {
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
				Name: "Location",
				Header: []string{
					"Package",
					"Location",
					"Min. Recommended Version",
				},
				Rows: []map[string]string{{
					"Package":                  key.name,
					"Location":                 key.path,
					"Min. Recommended Version": det.fixedBy,
				}},
			},
			vp,
		}

		// Build the vulnerability.
		state.AddVulnerabilities(vuln)
	}
}

func processSecrets(results scanResponse, vuln report.Vulnerability, target, branch string, state checkstate.State) {
	for _, tt := range results {
		for _, ts := range tt.Secrets {

			var sbAll, sbCause strings.Builder
			for _, b := range ts.Code.Lines {
				sbAll.WriteString(b.Content)
				if b.IsCause {
					sbCause.WriteString(b.Content)
				}
			}

			vuln.Details = fmt.Sprintf("This secret was found by the trivy rule '%s'.", ts.RuleID)
			vuln.AffectedResource = string(hex.EncodeToString(sha256.New().Sum([]byte(sbAll.String())))[1:48])
			affectedResourceString := computeAffectedResource(target, branch, tt.Target, ts.StartLine)
			vuln.AffectedResourceString = affectedResourceString
			vuln.Fingerprint = helpers.ComputeFingerprint()
			vuln.Resources = []report.ResourcesGroup{{
				Name: "Secrets found",
				Header: []string{
					"RuleID",
					"Title",
					"Cause",
					"StartLine",
					"EndLine",
					"Link",
				},
				Rows: []map[string]string{
					{
						"RuleID":    ts.RuleID,
						"Title":     ts.Title,
						"Cause":     sbCause.String(),
						"StartLine": fmt.Sprint(ts.StartLine),
						"EndLine":   fmt.Sprint(ts.EndLine),
						"Link":      fmt.Sprintf("[Link](%s)", affectedResourceString),
					},
				},
			}}
			state.AddVulnerabilities(vuln)
		}
	}
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
