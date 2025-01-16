/*
Copyright 2019 Adevinta
*/

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	check "github.com/adevinta/vulcan-check-sdk"
	"github.com/adevinta/vulcan-check-sdk/helpers"
	checkstate "github.com/adevinta/vulcan-check-sdk/state"
	report "github.com/adevinta/vulcan-report"
	version "github.com/hashicorp/go-version"
)

type result []sshScanReport
type sshScanReport struct {
	Fingerprints struct {
		DSA struct {
			KnownBad string `json:"known_bad"`
			MD5      string `json:"md5"`
			SHA1     string `json:"sha1"`
			SHA256   string `json:"sha256"`
		} `json:"dsa"`
		RSA struct {
			KnownBad string `json:"known_bad"`
			MD5      string `json:"md5"`
			SHA1     string `json:"sha1"`
			SHA256   string `json:"sha256"`
		} `json:"rsa"`
	} `json:"fingerprints"`
	Compliance struct {
		Recommendations []string `json:"recommendations"`
		References      []string `json:"references"`
		Policy          string   `json:"policy"`
		Grade           string   `json:"grade"`
		Compliant       bool     `json:"compliant"`
	} `json:"compliance"`
	KeyAlgorithms            []string `json:"key_algorithms"`
	ServerHostAlgorithms     []string `json:"server_host_key_algorithms"`
	EncryptionAlgorithmsC2S  []string `json:"encryption_algorithms_client_to_server"`
	EncryptionAlgorithmsS2C  []string `json:"encryption_algorithms_server_to_client"`
	MACAlgorithmsC2S         []string `json:"mac_algorithms_client_to_server"`
	MACAlgorithmsS2C         []string `json:"mac_algorithms_server_to_client"`
	CompressionAlgorithmsC2S []string `json:"compression_algorithms_client_to_server"`
	CompressionAlgorithmsS2C []string `json:"compression_algorithms_server_to_client"`
	LanguagesC2S             []string `json:"languages_client_to_server"`
	LanguagesS2C             []string `json:"languages_server_to_client"`
	AuthenticationMethods    []string `json:"auth_methods"`
	DuplicateHostKeyIPs      []string `json:"duplicate_host_key_ips"`
	StartTime                string   `json:"start_time"`
	EndTime                  string   `json:"end_time"`
	Error                    string   `json:"error"`
	ScanVersion              string   `json:"ssh_scan_version"`
	Hostname                 string   `json:"hostname"`
	IP                       string   `json:"ip"`
	ServerBanner             string   `json:"server_banner"`
	OS                       string   `json:"os"`
	OSCPE                    string   `json:"os_cpe"`
	SSHLib                   string   `json:"ssh_lib"`
	SSHLibCPE                string   `json:"ssh_lib_cpe"`
	Port                     int      `json:"port"`
	ScanDurationInSeconds    float64  `json:"scan_duration_seconds"`
	//SSHVersion               float64  `json:"ssh_version"`	// if port is closed this field is string e.g. "ssh_version": "unknown"
}

var (
	pathToScanner = "ssh_scan"
	checkName     = "vulcan-exposed-ssh"
	logger        = check.NewCheckLog(checkName)
	policyFile    = "policy/modern.yml"
	defaultPorts  = []string{
		"22",    // standard SSH port
		"2222",  // common alternative for standard SSH port
		"33001", // IBM Aspera High-Speed File Transfer Software recommended SSH port
	}
	bannerRE       *regexp.Regexp
	c6, c7, c8     version.Constraints
	exposedSSHVuln = report.Vulnerability{
		CWEID:           284,
		Summary:         "Exposed SSH Ports",
		ImpactDetails:   "An attacker may be able to use the exposed port to exploit a vulnerability in the service.",
		Score:           report.SeverityThresholdMedium,
		Recommendations: []string{"Block access to SSH ports from the internet."},
		Labels:          []string{"issue", "ssh"},
	}
	libsshVuln = report.Vulnerability{
		CWEID:           288,
		Summary:         "Authentication Bypass In libssh",
		ImpactDetails:   "An attacker may be able to authenticate without any credentials.",
		Score:           report.SeverityThresholdHigh,
		Recommendations: []string{"Update to the latest version of the libssh library."},
		References:      []string{"https://www.libssh.org/2018/10/16/libssh-0-8-4-and-0-7-6-security-and-bugfix-release/", "https://www.libssh.org/security/advisories/CVE-2018-10933.txt"},
		Labels:          []string{"issue", "ssh"},
	}
	passAuthVuln = report.Vulnerability{
		CWEID:           309,
		Summary:         "SSH Allows Authentication Using Passwords",
		ImpactDetails:   "An attacker can try to gain access to the host by trying brute forcing users and passwords.",
		Score:           report.SeverityThresholdMedium,
		Recommendations: []string{},
		References:      []string{"https://wiki.mozilla.org/Security/Guidelines/OpenSSH"},
		Labels:          []string{"issue", "ssh"},
	}
	allowSSHv1Vuln = report.Vulnerability{
		CWEID:           937,
		Summary:         "Support For SSHv1",
		ImpactDetails:   "Version 1 of the SSH protocol contains fundamental weaknesses which make sessions vulnerable to man-in-the-middle attacks.",
		Score:           report.SeverityThresholdMedium,
		Recommendations: []string{"Disable SSH version 1."},
		References:      []string{"https://wiki.mozilla.org/Security/Guidelines/OpenSSH"},
		Labels:          []string{"issue", "ssh"},
	}
	weakKexConfigVuln = report.Vulnerability{
		CWEID:           326,
		Summary:         "Service Uses Weak Key Exchange Algorithms",
		ImpactDetails:   "An attacker can compromise secure channel due to use of weak ciphers and algorithms.",
		Score:           report.SeverityThresholdLow,
		Recommendations: []string{},
		References:      []string{"https://wiki.mozilla.org/Security/Guidelines/OpenSSH"},
		Labels:          []string{"issue", "ssh"},
	}
	weakCiphersConfigVuln = report.Vulnerability{
		CWEID:           326,
		Summary:         "Service Uses Weak Ciphers",
		ImpactDetails:   "An attacker can compromise secure channel due to use of weak ciphers and algorithms.",
		Score:           report.SeverityThresholdLow,
		Recommendations: []string{},
		References:      []string{"https://wiki.mozilla.org/Security/Guidelines/OpenSSH"},
		Labels:          []string{"issue", "ssh"},
	}
	weakMACsConfigVuln = report.Vulnerability{
		CWEID:           326,
		Summary:         "Service Uses Weak Message Authentication Codes",
		ImpactDetails:   "An attacker can compromise secure channel due to use of weak ciphers and algorithms.",
		Score:           report.SeverityThresholdLow,
		Recommendations: []string{},
		References:      []string{"https://wiki.mozilla.org/Security/Guidelines/OpenSSH"},
		Labels:          []string{"issue", "ssh"},
	}
	comprAlgoConfigVuln = report.Vulnerability{
		Summary:         "Compression Algorithms Misconfiguration",
		Score:           report.SeverityThresholdNone,
		Recommendations: []string{},
		References:      []string{"https://wiki.mozilla.org/Security/Guidelines/OpenSSH"},
		Labels:          []string{"issue", "ssh"},
	}
)

type options struct {
	// List of potential ssh ports to scan for.
	Ports []string `json:"ports"`
	// Scanning allowed open SSH Ports
	AllowedOpenPorts bool `json:"allowed"`
}

type runner struct {
	output []byte
	notes  string
}

func (r *runner) gradeVuln() ([]report.Vulnerability, error) {
	kexRecommendationPattern := "key exchange algorithms"
	ciphersRecommendationPattern := "encryption ciphers"
	macsRecommendationPattern := "MAC algorithms"
	authRecommendationPattern := "authentication methods"
	sshv1RecommendationPattern := "your ssh version"
	comprRecommendationPattern := "compression algorithms"
	var vulnArray []report.Vulnerability
	var res result

	if err := json.Unmarshal(r.output, &res); err != nil {
		return nil, err
	}

	for _, i := range res {
		if i.Error != "" {
			// NOTE: this doesn't cover different types of errors that ssh_scan can produce
			continue
		}
		// Exposed SSH
		v := exposedSSHVuln
		v.Details += fmt.Sprintf("* Exposed SSH Port in %v\n", i.Port)
		v.AffectedResource = fmt.Sprintf("%d/%s", i.Port, "tcp")
		v.Fingerprint = helpers.ComputeFingerprint()
		vulnArray = append(vulnArray, v)

		if strings.Contains(strings.ToLower(i.ServerBanner), "libssh") {
			r.notes += fmt.Sprintf("* libssh possibly detected in port %v: %v\n", i.Port, i.ServerBanner)
		}

		// Check libssh auth bypass vulnerability (CVE-2018-10933).
		if i.SSHLib == "libssh" {
			matches := bannerRE.FindStringSubmatch(i.ServerBanner)
			if len(matches) > 0 {
				ver, err := version.NewVersion(matches[1])
				// Don't stop parsing the results if a version hasn't been found.
				if err == nil {
					if c6.Check(ver) || c7.Check(ver) || c8.Check(ver) {
						v := libsshVuln
						v.Details += fmt.Sprintf("* libssh version %v in port %v may be vulnerable\n", ver.String(), i.Port)
						v.AffectedResource = fmt.Sprintf("%d/%s", i.Port, "tcp")
						v.Fingerprint = helpers.ComputeFingerprint()
						vulnArray = append(vulnArray, v)
					}
				}
			}
		}

		r.notes += fmt.Sprintf("* Banner for port %v:\n %v\n", i.Port, i.ServerBanner)
		r.notes += fmt.Sprintf("* SSHLib for port %v:\n %v\n", i.Port, i.SSHLib)
		r.notes += fmt.Sprintf("* SSHLibCPE for port %v:\n %v\n", i.Port, i.SSHLibCPE)

		// Skip if compliant
		if i.Compliance.Compliant {
			continue
		}
		// Evaluate recommendations and map them to vulnerabilities
		for _, j := range i.Compliance.Recommendations {
			if strings.Contains(j, kexRecommendationPattern) {
				v := weakKexConfigVuln
				v.AffectedResource = fmt.Sprintf("%d/%s", i.Port, "tcp")
				v.Recommendations = append(v.Recommendations, j)
				v.Details += fmt.Sprintf("* Affected port: %v\n", i.Port)
				v.Fingerprint = helpers.ComputeFingerprint()
				vulnArray = append(vulnArray, v)
			} else if strings.Contains(j, ciphersRecommendationPattern) {
				v := weakCiphersConfigVuln
				v.Recommendations = append(v.Recommendations, j)
				v.Details += fmt.Sprintf("* Affected port: %v\n", i.Port)
				v.AffectedResource = fmt.Sprintf("%d/%s", i.Port, "tcp")
				v.Fingerprint = helpers.ComputeFingerprint()
				vulnArray = append(vulnArray, v)
			} else if strings.Contains(j, macsRecommendationPattern) {
				v := weakMACsConfigVuln
				v.Recommendations = append(v.Recommendations, j)
				v.Details += fmt.Sprintf("* Affected port: %v\n", i.Port)
				v.AffectedResource = fmt.Sprintf("%d/%s", i.Port, "tcp")
				v.Fingerprint = helpers.ComputeFingerprint()
				vulnArray = append(vulnArray, v)
			} else if strings.Contains(j, authRecommendationPattern) {
				v := passAuthVuln
				v.Recommendations = append(v.Recommendations, j)
				v.Details += fmt.Sprintf("* Affected port: %v\n", i.Port)
				v.AffectedResource = fmt.Sprintf("%d/%s", i.Port, "tcp")
				v.Fingerprint = helpers.ComputeFingerprint()
				vulnArray = append(vulnArray, v)
			} else if strings.Contains(j, sshv1RecommendationPattern) {
				v := allowSSHv1Vuln
				v.Recommendations = append(v.Recommendations, j)
				v.Details += fmt.Sprintf("* Affected port: %v\n", i.Port)
				v.AffectedResource = fmt.Sprintf("%d/%s", i.Port, "tcp")
				v.Fingerprint = helpers.ComputeFingerprint()
				vulnArray = append(vulnArray, v)
			} else if strings.Contains(j, comprRecommendationPattern) {
				v := comprAlgoConfigVuln
				v.Recommendations = append(v.Recommendations, j)
				v.Details += fmt.Sprintf("* Affected port: %v\n", i.Port)
				v.AffectedResource = fmt.Sprintf("%d/%s", i.Port, "tcp")
				v.Fingerprint = helpers.ComputeFingerprint()
				vulnArray = append(vulnArray, v)
			}
		}
	}
	return vulnArray, nil
}

// Accumulate output to build the raw report.
func (r *runner) ProcessOutputChunk(chunk []byte) bool {
	r.output = append(r.output, chunk...)
	return true
}

func (r *runner) newSSHScan(ctx context.Context, target string, ports []string) error {
	processRunner := check.NewProcessChecker(pathToScanner, []string{"-P", policyFile, "-t", target, "-p", strings.Join(ports, ",")}, bufio.ScanLines, r)
	_, err := processRunner.Run(ctx)
	return err
}

func main() {
	run := func(ctx context.Context, target, assetType, optJSON string, state checkstate.State) error {
		var err error
		bannerRE, err = regexp.Compile(`^SSH-[0-9A-Za-z.]+-libssh-([[:graph:]]+)[[:space:]]*`)
		if err != nil {
			return err
		}
		c6, err = version.NewConstraint(">= 0.6, < 0.7")
		if err != nil {
			return err
		}
		c7, err = version.NewConstraint(">= 0.7, < 0.7.6")
		if err != nil {
			return err
		}
		c8, err = version.NewConstraint(">= 0.8, < 0.8.4")
		if err != nil {
			return err
		}

		var opt options
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

		if len(opt.Ports) == 0 {
			opt.Ports = defaultPorts
		} else if opt.AllowedOpenPorts {
			exposedSSHVuln.Score = report.SeverityThresholdNone
		}

		if target == "" {
			return fmt.Errorf("check target missing")
		}

		var r runner
		if err := r.newSSHScan(ctx, target, opt.Ports); err != nil {
			return err
		}

		vulnArray, err := r.gradeVuln()
		if err != nil {
			return err
		}

		state.AddVulnerabilities(vulnArray...)
		state.Data = r.output
		state.Notes = r.notes

		return nil
	}

	c := check.NewCheckFromHandler(checkName, run)
	c.RunAndServe()
}
