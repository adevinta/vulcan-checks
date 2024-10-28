/*
Copyright 2019 Adevinta
*/

package main

import (
	"fmt"
	"net"
	"net/mail"
	"strconv"
	"strings"

	report "github.com/adevinta/vulcan-report"
)

// DMARC represents a DMARC dns record
// https://tools.ietf.org/html/rfc7489#section-6.4
type DMARC struct {
	version string
	request string
	sp      string
	rua     string
	ruf     string
	adkim   string
	aspf    string
	ri      string
	fo      string
	rf      string
	pct     string

	otherFields map[string]string

	vulnerabilities []report.Vulnerability

	target string
}

// Domain Owner DMARC preferences are stored as DNS TXT records in subdomains named "_dmarc".
// https://tools.ietf.org/html/rfc7489#section-6.1
const prefix = "_dmarc."
const sep = ";"

func (dmarc *DMARC) evaluate() {
	if dmarc.request == "none" {
		vuln := vulns["tag-p-is-none"]
		vuln.AffectedResource = dmarc.target
		dmarc.vulnerabilities = append(dmarc.vulnerabilities, vuln)
	}

	if dmarc.request == "quarantine" {
		vuln := vulns["tag-p-is-quarantine"]
		vuln.AffectedResource = dmarc.target
		dmarc.vulnerabilities = append(dmarc.vulnerabilities, vuln)
	}

	if len(dmarc.rua) == 0 {
		vuln := vulns["tag-rua-not-configured"]
		vuln.AffectedResource = dmarc.target
		dmarc.vulnerabilities = append(dmarc.vulnerabilities, vuln)
	}

	if len(dmarc.ruf) == 0 {
		vuln := vulns["tag-ruf-not-configured"]
		vuln.AffectedResource = dmarc.target
		dmarc.vulnerabilities = append(dmarc.vulnerabilities, vuln)
	}

	if len(dmarc.pct) > 0 && dmarc.pct != "100" {
		vuln := vulns["tag-pct-not-100"]
		vuln.AffectedResource = dmarc.target
		dmarc.vulnerabilities = append(dmarc.vulnerabilities, vuln)
	}

	if len(dmarc.adkim) > 0 && dmarc.adkim != "r" && dmarc.adkim != "s" {
		vuln := vulns["tag-adkim-not-valid"]
		vuln.AffectedResource = dmarc.target
		dmarc.vulnerabilities = append(dmarc.vulnerabilities, vuln)
	}

	if len(dmarc.aspf) > 0 && dmarc.aspf != "r" && dmarc.aspf != "s" {
		vuln := vulns["tag-aspf-not-valid"]
		vuln.AffectedResource = dmarc.target
		dmarc.vulnerabilities = append(dmarc.vulnerabilities, vuln)
	}

	if len(dmarc.sp) > 0 && dmarc.sp != "none" && dmarc.sp != "reject" && dmarc.sp != "quarantine" {
		vuln := vulns["tag-sp-not-valid"]
		vuln.AffectedResource = dmarc.target
		dmarc.vulnerabilities = append(dmarc.vulnerabilities, vuln)
	}

	if len(dmarc.fo) > 0 && dmarc.fo != "0" && dmarc.fo != "1" && dmarc.fo != "d" && dmarc.fo != "s" {
		vuln := vulns["tag-fo-not-valid"]
		vuln.AffectedResource = dmarc.target
		dmarc.vulnerabilities = append(dmarc.vulnerabilities, vuln)
	}

	if len(dmarc.rf) > 0 && dmarc.rf != "afrf" {
		vuln := vulns["tag-rf-not-valid"]
		vuln.AffectedResource = dmarc.target
		dmarc.vulnerabilities = append(dmarc.vulnerabilities, vuln)
	}

	if len(dmarc.ri) > 0 {
		_, err := strconv.Atoi(dmarc.ri)
		if err != nil {
			vuln := vulns["tag-ri-not-valid"]
			vuln.AffectedResource = dmarc.target
			dmarc.vulnerabilities = append(dmarc.vulnerabilities, vuln)
		}
	}

	if len(dmarc.rua) > 0 {
		vuln := vulns["tag-rua-not-valid-mailto"]
		vuln.AffectedResource = dmarc.target
		dmarc.vulnerabilities = append(dmarc.vulnerabilities, vuln)
	}

	if len(dmarc.ruf) > 0 {
		vuln := vulns["tag-ruf-not-valid-mailto"]
		vuln.AffectedResource = dmarc.target
		dmarc.vulnerabilities = append(dmarc.vulnerabilities, vuln)
	}

}

func (dmarc *DMARC) validateEmailList(list, vulnerabilityName string) {
	emails := strings.Split(list, ",")
	for _, email := range emails {
		if strings.HasPrefix(email, "mailto:") {
			_, err := mail.ParseAddress(email[7:])
			if err != nil {
				vuln := vulns[vulnerabilityName]
				vuln.AffectedResource = dmarc.target
				dmarc.vulnerabilities = append(dmarc.vulnerabilities, vuln)
				break
			}
		} else {
			vuln := vulns[vulnerabilityName]
			vuln.AffectedResource = dmarc.target
			dmarc.vulnerabilities = append(dmarc.vulnerabilities, vuln)
			break
		}
	}
}

func (dmarc *DMARC) parse(domain string) bool {
	records, _ := net.LookupTXT(prefix + domain)
	return dmarc.parseTxtRecords(records)
}

func (dmarc *DMARC) parseTxtRecords(records []string) bool {
	foundDmarc := false
	for _, record := range records {
		if dmarc.parseFields(record) {
			if foundDmarc {
				vuln := vulns["multiple-dmarc-found"]
				vuln.AffectedResource = dmarc.target
				dmarc.vulnerabilities = append(dmarc.vulnerabilities, vuln)
				return false
			}

			foundDmarc = true
		}
	}

	if !foundDmarc && len(dmarc.vulnerabilities) == 0 {
		vuln := vulns["dmarc-not-found"]
		vuln.AffectedResource = dmarc.target
		dmarc.vulnerabilities = append(dmarc.vulnerabilities, vuln)
		return false
	}

	return true
}

func (dmarc *DMARC) parseFields(record string) bool {
	// A DMARC policy record MUST comply with the formal specification found
	// in Section 6.4 in that the "v" and "p" tags MUST be present and MUST
	// appear in that order.
	tagVersion, valueVersion, txtRecord, err := extractTagAndValue(record)
	if err != nil {
		// error trying to extract the first tag, score zero
		vuln := vulns["unable-to-parse-tags"]
		vuln.AffectedResource = dmarc.target
		dmarc.vulnerabilities = append(dmarc.vulnerabilities, vuln)
		return false
	}

	if tagVersion != "v" {
		// the first tag is diferent than 'v', the spec requires the first field to be 'v'
		vuln := vulns["v-and-p-invalid-or-missing"]
		vuln.AffectedResource = dmarc.target
		dmarc.vulnerabilities = append(dmarc.vulnerabilities, vuln)
		return false
	}

	if valueVersion != "DMARC1" {
		// the first tag is 'v' but the value is diferent than 'DMARC1' , the spec requires the version value to be set to 'DMARC1'
		vuln := vulns["tag-v-wrong-value"]
		vuln.AffectedResource = dmarc.target
		dmarc.vulnerabilities = append(dmarc.vulnerabilities, vuln)
		return false
	}

	tagRequest, valueRequest, txtRecord, err := extractTagAndValue(txtRecord)
	if err != nil {
		// error trying to extract the second tag, score zero
		vuln := vulns["unable-to-parse-tags"]
		vuln.AffectedResource = dmarc.target
		dmarc.vulnerabilities = append(dmarc.vulnerabilities, vuln)
		return false
	}

	isValidRequest := make(map[string]bool)
	isValidRequest["none"] = true
	isValidRequest["quarantine"] = true
	isValidRequest["reject"] = true

	if tagRequest != "p" {
		// the second tag is diferent than 'p' , the spec requires the second field to be 'v'
		vuln := vulns["v-and-p-invalid-or-missing"]
		vuln.AffectedResource = dmarc.target
		dmarc.vulnerabilities = append(dmarc.vulnerabilities, vuln)
		return false
	}

	if !isValidRequest[valueRequest] {
		// the second tag is 'p' but the value is not a valid one [none, quarantine, reject]
		vuln := vulns["tag-p-wrong-value"]
		vuln.AffectedResource = dmarc.target
		dmarc.vulnerabilities = append(dmarc.vulnerabilities, vuln)
	}

	dmarc.version = valueVersion
	dmarc.request = valueRequest
	dmarc.otherFields = make(map[string]string)

	// parse the remaining fields
	for len(txtRecord) > 0 {
		var tag string
		var value string
		tag, value, txtRecord, err = extractTagAndValue(txtRecord)
		if err != nil {
			// error trying to extract the tag, this means a malformed record, score zero
			vuln := vulns["unable-to-parse-tags"]
			vuln.AffectedResource = dmarc.target
			dmarc.vulnerabilities = append(dmarc.vulnerabilities, vuln)
			return false
		}

		if tag == "sp" {
			dmarc.sp = value
			continue
		}

		if tag == "rua" {
			dmarc.rua = value
			continue
		}

		if tag == "ruf" {
			dmarc.ruf = value
			continue
		}

		if tag == "adkim" {
			dmarc.adkim = value
			continue
		}

		if tag == "aspf" {
			dmarc.aspf = value
			continue
		}

		if tag == "ri" {
			dmarc.ri = value
			continue
		}

		if tag == "fo" {
			dmarc.fo = value
			continue
		}

		if tag == "rf" {
			dmarc.rf = value
			continue
		}

		if tag == "pct" {
			dmarc.pct = value
			continue
		}

		dmarc.otherFields[tag] = value
	}

	return true
}

func extractTagAndValue(txtRecord string) (tag, value, remainingRecord string, err error) {
	if len(strings.Trim(txtRecord, " ")) == 0 {
		return
	}

	index := strings.Index(txtRecord, sep)
	if index < 0 {
		index = len(txtRecord)
	}

	tagAndValue := txtRecord[:index]
	parts := strings.Split(tagAndValue, "=")
	if len(parts) != 2 {
		err = fmt.Errorf("Malformed tag: %v", tagAndValue)
		return "", "", "", err
	}
	tag = strings.Trim(parts[0], " ")
	value = strings.Trim(parts[1], " ")
	if index+1 > len(txtRecord) {
		remainingRecord = ""
	} else {
		remainingRecord = txtRecord[index+1:]
	}
	return tag, value, strings.TrimLeft(remainingRecord, " "), nil
}

func checkMX(domain string) bool {
	records, _ := net.LookupMX(domain)
	return len(records) > 0
}
