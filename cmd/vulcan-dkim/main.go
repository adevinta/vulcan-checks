package main

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"strings"

	"github.com/sirupsen/logrus"

	check "github.com/adevinta/vulcan-check-sdk"
	"github.com/adevinta/vulcan-check-sdk/state"
	report "github.com/adevinta/vulcan-report"
)

// NOTE: should we drop all scores to NONE? 'missing DKIM' is rated as INFO on
// Bugcrowd database: https://github.com/bugcrowd/vulnerability-rating-taxonomy/blob/a6dcfb43cf26004ab20320071b84f59beda49e22/vulnerability-rating-taxonomy.json#L134

var (
	checkName       = "vulcan-dkim"
	logger          = check.NewCheckLog(checkName)
	defaultSelector = []string{"default"}
	recommendations = map[string]string{
		"v-tag":         "Set Version 'v' tag (recommended; plain-text; default value 'DKIM1'; example: 'v=DKIM1'). Warning: some ISPs may mark the DKIM authentication check as neutral if the version tag is invalid.",
		"p-tag-not-rsa": "Set Public key 'p' tag (required; base64; no default value; example: 'p='+base64(der_enc_public_key). Public Key is not RSA key.",
		"p-tag-not-der": "Set Public key 'p' tag (required; base64; no default value; example: 'p='+base64(der_enc_public_key). Public key is not DER encoded.",
		"p-tag-empty":   "An empty value means that this public key has been revoked. In case of misconfiguration set Public key 'p' tag (required; base64; no default value; example: 'p='+base64(public_key).",
		"p-tag-b64":     "Public key ('p' tag) must be base64 encoded",
		"h-tag":         "Set Hash algorithms 'h' tag (optional; plain-text; default value '*' [allow all]; example: 'h=sha256'). Recommended algorithm 'sha256'.",
		"k-tag":         "Set Key type 'k' tag (optional; plain-text; default value 'rsa'; example 'k=rsa') or remove malformed tag for default value. Currently only 'rsa' is recognized and it's a default value so it's convenient to remove the malformed tag.",
		"s-tag":         "Set Service type 's' tag (optional; plan-text; default value '*' [allow all]; example: 's=email') or remove malformed tag for default value. Currently only 'email' is recognized.",
		"t-tag":         "Set Flags 't' tag (optional; plain-text; no default value; example 't=s')  or remove malformed tag for default value. Set to 's' for domain alignment (strict mode), 'y' for test mode or remove malformed tag.",
	}
	vulns = map[string]report.Vulnerability{
		"dkim-not-found": report.Vulnerability{
			CWEID:         358,
			Summary:       "DKIM DNS Record Not Found",
			Description:   "DKIM DNS TXT record has not been found in the scanned domain. Domain Keys Identified Mail (DKIM) is an email authentication method designed to detect email spoofing. It allows the receiver to check that an email claimed to have come from a specific domain was indeed authorized by the owner of that domain. It is intended to prevent forged sender addresses in emails, a technique often used in phishing and email spam.",
			Score:         report.SeverityThresholdLow,
			ImpactDetails: "By setting DKIM on your DNS server you're adding an additional way to tell your receivers \"yes, it’s really me who's sending this message\", which means increasing the deliverability of your emails and your sender reputation.",
			References: []string{
				"https://DKIM.org/",
				"https://en.wikipedia.org/wiki/DomainKeys_Identified_Mail",
				"https://tools.ietf.org/html/rfc6376#page-53",
				"https://www.emailarchitect.net/domainkeys/doc/html/selector.htm",
			},
			Recommendations: []string{
				"Create a valid DKIM DNS Record",
				"For easier deployment of DKIM record in AWS Route53 check our CloudFormation Template in References",
			},
			Details: "Selector: %s\n\n. You can check DKIM DNS record running the following command: dig -t txt %s",
		},
		"dkim-malformed": report.Vulnerability{
			CWEID:         358,
			Summary:       "Misconfiguration Of DKIM Record",
			Description:   "Invalid DKIM DNS TXT Record.",
			Score:         report.SeverityThresholdMedium,
			ImpactDetails: "Domain Keys Identified Mail (DKIM) is an email authentication method designed to detect email spoofing. It allows the receiver to check that an email claimed to have come from a specific domain was indeed authorized by the owner of that domain. It is intended to prevent forged sender addresses in emails, a technique often used in phishing and email spam.",
			References: []string{
				"https://DKIM.org/",
				"https://en.wikipedia.org/wiki/DomainKeys_Identified_Mail",
				"https://tools.ietf.org/html/rfc6376#page-53",
			},
			Recommendations: []string{
				"Create a valid DKIM DNS TXT Record",
			},
			Details: "Selector: %s.",
		},
		"multiple-dkim-found": report.Vulnerability{
			CWEID:       358,
			Summary:     "Multiple DKIM Records Found",
			Description: "Multiple DKIM records found. Selector configuration will be picked randomly or DKIM will not be validated.",
			Score:       report.SeverityThresholdMedium,
			References: []string{
				"https://DKIM.org/",
				"https://en.wikipedia.org/wiki/DomainKeys_Identified_Mail",
				"https://tools.ietf.org/html/rfc6376",
			},
			Recommendations: []string{
				"Create a single record for DKIM.",
			},
			Details: "Selector: %s.",
		},
		"missing-v-tag": report.Vulnerability{
			CWEID:       358,
			Summary:     "DKIM Missing Version Tag",
			Description: "When Version tag is missing some ISPs may mark the DKIM authentication check as neutral if the version tag is invalid.",
			Score:       report.SeverityThresholdLow,
			References: []string{
				"https://DKIM.org/",
				"https://en.wikipedia.org/wiki/DomainKeys_Identified_Mail",
				"https://tools.ietf.org/html/rfc6376",
			},
			Recommendations: []string{
				recommendations["v-tag"],
			},
			Details: "Selector: %s.",
		},
		"t-tag-test-mode": report.Vulnerability{
			Summary: "DKIM Record In Test Mode",
			Score:   report.SeverityThresholdLow,
			References: []string{
				"https://DKIM.org/",
				"https://en.wikipedia.org/wiki/DomainKeys_Identified_Mail",
				"https://tools.ietf.org/html/rfc6376#page-53",
			},
			Details: "Selector: %s.",
		},
		"t-tag-strict-mode": report.Vulnerability{
			Summary: "DKIM Record In Strict Mode",
			Score:   report.SeverityThresholdNone,
			References: []string{
				"https://DKIM.org/",
				"https://en.wikipedia.org/wiki/DomainKeys_Identified_Mail",
				"https://tools.ietf.org/html/rfc6376#page-53",
			},
			Details: "Selector: %s.",
		},
		"sha1": report.Vulnerability{
			CWEID:   358,
			Summary: "DKIM Record Allows Use Of SHA1",
			Description: "SHA1 is considered insecure algorithm. Attacker could forge an email that would " +
				"pass as a legitimate due to collision of SHA1 hashes used to generate a DKIM signature.",
			Score: report.SeverityThresholdLow,
			References: []string{
				"https://DKIM.org/",
				"https://en.wikipedia.org/wiki/DomainKeys_Identified_Mail",
				"https://tools.ietf.org/html/rfc6376#page-53",
				"https://shattered.io/",
			},
			Recommendations: []string{
				recommendations["h-tag"],
			},
			Details: "Selector: %s.",
		},
		"revoked-key": report.Vulnerability{
			Summary:     "DKIM Key Revocation",
			Description: "An empty 'p' tag value means that this public key has been revoked.",
			Score:       report.SeverityThresholdNone,
			References: []string{
				"https://DKIM.org/",
				"https://en.wikipedia.org/wiki/DomainKeys_Identified_Mail",
				"https://tools.ietf.org/html/rfc6376#page-53",
			},
			Recommendations: []string{
				recommendations["p-tag-empty"],
			},
			Details: "Selector: %s.",
		},
		"weak-key": report.Vulnerability{
			Summary:     "DKIM Public Key Is Too Short",
			Description: "Using weak RSA keys can make it easier to attacker to forge the signature.",
			Score:       report.SeverityThresholdLow,
			References: []string{
				"https://DKIM.org/",
				"https://en.wikipedia.org/wiki/DomainKeys_Identified_Mail",
				"https://tools.ietf.org/html/rfc6376#page-53",
				"http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57Pt3r1.pdf",
				"https://gsuiteupdates.googleblog.com/2016/05/getting-rid-of-spoofers-digitally-sign.html",
			},
			Recommendations: []string{
				"DKIM should use at least 2048 bit RSA key. NIST recommends RSA 2048 bit Digital Signature keys used for authentication and non-repudiation (for Users or Devices)",
			},
			Details: "Selector: %s.\nBits of the key: %d.",
		},
		"unable-to-parse-tags": report.Vulnerability{
			CWEID:   358,
			Summary: "DKIM Unable To Parse Tags",
			Description: "DKIM records do not follow the extensible 'tag-value' syntax for DNS-based" +
				"key records defined in DKIM correctly.",
			Score:         report.SeverityThresholdMedium,
			ImpactDetails: "Domain Keys Identified Mail (DKIM) is an email authentication method designed to detect email spoofing. It allows the receiver to check that an email claimed to have come from a specific domain was indeed authorized by the owner of that domain. It is intended to prevent forged sender addresses in emails, a technique often used in phishing and email spam.",
			References: []string{
				"https://DKIM.org/",
				"https://en.wikipedia.org/wiki/DomainKeys_Identified_Mail",
				"https://tools.ietf.org/html/rfc6376#page-53",
			},
			Recommendations: []string{
				"Review the record syntax and fix/remove the invalid tags/values.",
			},
			Details: "Selector: %s.\nInvalid tag values: %v.",
		},
	}
)

//DKIM represents a DKIM dns record
//https://tools.ietf.org/html/rfc6376#page-53
type DKIM struct {
	version   string
	hash      string
	keyType   string
	notes     string
	publicKey string
	service   string
	flags     string

	selector        string
	otherFields     map[string]string
	vulnerabilities []report.Vulnerability
}

const (
	domainSchema = "%s._domainkey.%s"
	dkimVersion  = "DKIM1"
	sep          = ";"
	sep2         = ","
)

type options struct {
	// List of potential dkim selectors.
	Selectors []string `json:"selectors"`
}

func main() {
	run := func(ctx context.Context, target, targetType string, optJSON string, state state.State) (err error) {
		var opt options
		if optJSON != "" {
			if err := json.Unmarshal([]byte(optJSON), &opt); err != nil {
				return err
			}
		}

		// Only test DKIM if the domain have a MX entry on DNS
		if !checkMX(target) {
			return nil
		}

		// If SPF record exists, test DKIM if SPF does n
		if checkSPF(target) {
			return nil
		}

		if len(opt.Selectors) == 0 {
			opt.Selectors = defaultSelector
		}

		for _, s := range opt.Selectors {
			logger.WithFields(logrus.Fields{
				"domain":   target,
				"selector": s,
			}).Debug("requesting selector")

			dkim := DKIM{
				hash:    "*",
				keyType: "rsa",
				service: "*",
				notes:   "",
				flags:   "",
			}
			dkim.selector = s
			if dkim.parse(target) {
				dkim.evaluate()
			}

			if len(dkim.vulnerabilities) > 0 {
				for _, vulnerability := range dkim.vulnerabilities {
					state.AddVulnerabilities(vulnerability)
				}
			}
			logger.WithFields(logrus.Fields{
				"dkim_response": dkim,
			}).Debug("response received")
		}

		return nil
	}
	c := check.NewCheckFromHandler(checkName, run)

	c.RunAndServe()
}

func (dkim *DKIM) evaluate() {
	// START malformed record
	malfRecommendations := []string{}
	// Check Version
	if dkim.version != dkimVersion {
		vuln := vulns["missing-v-tag"]
		vuln.Details = fmt.Sprintf(vuln.Details, dkim.selector)
		dkim.vulnerabilities = append(dkim.vulnerabilities, vuln)
	}
	// Check Hash Algorithm
	// Hash algorithms can be a colon-separated list
	for _, i := range strings.Split(dkim.hash, sep2) {
		if i != "sha1" && i != "sha256" && i != "*" {
			malfRecommendations = append(malfRecommendations, recommendations["h-tag"])
		} else if i != "sha256" {
			vuln := vulns["sha1"]
			vuln.Details = fmt.Sprintf(vuln.Details, dkim.selector)
			dkim.vulnerabilities = append(dkim.vulnerabilities, vuln)
		}
	}
	// Check Key Type
	if dkim.keyType != "rsa" {
		malfRecommendations = append(malfRecommendations, recommendations["k-tag"])
	}
	// Check Services
	// Services can be a colon-separated list
	for _, i := range strings.Split(dkim.service, sep2) {
		if i != "email" && i != "*" {
			malfRecommendations = append(malfRecommendations, recommendations["s-tag"])
		}
	}
	// Check Flags
	// Flags can be a colon-separated list
	for _, i := range strings.Split(dkim.flags, sep2) {
		if i != "" && i != "y" && i != "s" {
			malfRecommendations = append(malfRecommendations, recommendations["t-tag"])
		} else if i == "y" {
			vuln := vulns["t-tag-test-mode"]
			vuln.Details = fmt.Sprintf(vuln.Details, dkim.selector)
			dkim.vulnerabilities = append(dkim.vulnerabilities, vuln)
		} else if i == "t" {
			vuln := vulns["t-tag-strict-mode"]
			vuln.Details = fmt.Sprintf(vuln.Details, dkim.selector)
			dkim.vulnerabilities = append(dkim.vulnerabilities, vuln)
		}
	}
	// Check Public Key
	if dkim.publicKey == "" {
		vuln := vulns["revoked-key"]
		vuln.Details = fmt.Sprintf(vuln.Details, dkim.selector)
		dkim.vulnerabilities = append(dkim.vulnerabilities, vuln)
	} else {
		derKey, err := base64.StdEncoding.DecodeString(dkim.publicKey)
		if err != nil {
			malfRecommendations = append(malfRecommendations, recommendations["p-tag-b64"])
		} else {
			pub, err := x509.ParsePKIXPublicKey(derKey)
			if err != nil {
				malfRecommendations = append(malfRecommendations, recommendations["p-tag-not-der"])
			} else {
				switch pub := pub.(type) {
				case *rsa.PublicKey:
					// check length of RSA key
					keyLength := pub.N.BitLen()
					if keyLength < 2047 {
						vuln := vulns["weak-key"]
						vuln.Details = fmt.Sprintf(vuln.Details, dkim.selector, keyLength)
						dkim.vulnerabilities = append(dkim.vulnerabilities, vuln)
					}
				default:
					malfRecommendations = append(malfRecommendations, recommendations["p-tag-not-rsa"])
				}
			}
		}
	}
	// Check for invalid tags
	if len(dkim.otherFields) > 0 {
		tmpArray := []string{}
		for k, v := range dkim.otherFields {
			tmpArray = append(tmpArray, fmt.Sprintf("%s=%v", k, v))
		}
		vuln := vulns["unable-to-parse-tags"]
		vuln.Details = fmt.Sprintf(vuln.Details, dkim.selector, tmpArray)
	}
	// END malformed record
	if len(malfRecommendations) > 0 {
		vuln := vulns["dkim-malformed"]
		vuln.Details = fmt.Sprintf(vuln.Details, dkim.selector)
		vuln.Recommendations = append(vuln.Recommendations, malfRecommendations...)
		dkim.vulnerabilities = append(dkim.vulnerabilities, vuln)
	}
}

func (dkim *DKIM) parse(domain string) bool {
	txtRecord := fmt.Sprintf(domainSchema, dkim.selector, domain)
	records, _ := net.LookupTXT(txtRecord)
	return dkim.parseTxtRecords(records, txtRecord)
}

func (dkim *DKIM) parseTxtRecords(records []string, txtRecord string) bool {
	if len(records) < 1 {
		vuln := vulns["dkim-not-found"]
		vuln.Details = fmt.Sprintf(vuln.Details, dkim.selector, txtRecord)
		dkim.vulnerabilities = append(dkim.vulnerabilities, vuln)
		return false
	} else if len(records) > 1 {
		vuln := vulns["multiple-dkim-found"]
		vuln.Details = fmt.Sprintf(vuln.Details, dkim.selector)
		dkim.vulnerabilities = append(dkim.vulnerabilities, vuln)
		return false
	}
	return dkim.parseFields(records[0])
}

func (dkim *DKIM) parseFields(record string) bool {
	tagAndValue := strings.Split(strings.Replace(record, " ", "", -1), sep)
	var dkimMap = map[string]string{}
	for _, i := range tagAndValue {
		if len(strings.Trim(i, " ")) > 0 {
			vuln := strings.Split(i, "=")
			if len(vuln) == 2 {
				dkimMap[vuln[0]] = vuln[1]
			}
		}
	}

	key := "v"
	tag, ok := dkimMap[key]
	if ok {
		dkim.version = tag
		delete(dkimMap, key)
	}
	key = "h"
	tag, ok = dkimMap[key]
	if ok {
		dkim.hash = tag
		delete(dkimMap, key)
	}
	key = "k"
	tag, ok = dkimMap[key]
	if ok {
		dkim.keyType = tag
		delete(dkimMap, key)
	}
	key = "n"
	tag, ok = dkimMap[key]
	if ok {
		dkim.notes = tag
		delete(dkimMap, key)
	}
	key = "p"
	tag, ok = dkimMap[key]
	if ok {
		dkim.publicKey = tag
		delete(dkimMap, key)
	}
	key = "s"
	tag, ok = dkimMap[key]
	if ok {
		dkim.service = tag
		delete(dkimMap, key)
	}
	key = "t"
	tag, ok = dkimMap[key]
	if ok {
		dkim.flags = tag
		delete(dkimMap, key)
	}
	dkim.otherFields = dkimMap
	return true
}

func checkMX(domain string) bool {
	records, _ := net.LookupMX(domain)
	return len(records) > 0
}

func checkSPF(domain string) bool {
	records, _ := net.LookupTXT(domain)
	for _, record := range records {
		// this domain does not send mail at all
		if strings.Contains(record, "v=spf1 -all") {
			return true
		}
	}
	return false
}
