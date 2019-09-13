package main

import (
	"fmt"
	"net"
	"net/mail"
	"strconv"
	"strings"

	"github.com/adevinta/vulcan-report"
)

//DMARC represents a DMARC dns record
//https://tools.ietf.org/html/rfc7489#section-6.4
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
}

// Domain Owner DMARC preferences are stored as DNS TXT records in subdomains named "_dmarc".
// https://tools.ietf.org/html/rfc7489#section-6.1
const prefix = "_dmarc."
const sep = ";"

func (dmarc *DMARC) evaluate() {
	if dmarc.request == "none" {
		dmarc.vulnerabilities = append(dmarc.vulnerabilities, vulns["tag-p-is-none"])
	}

	if dmarc.request == "quarantine" {
		dmarc.vulnerabilities = append(dmarc.vulnerabilities, vulns["tag-p-is-quarantine"])
	}

	if len(dmarc.rua) == 0 {
		dmarc.vulnerabilities = append(dmarc.vulnerabilities, vulns["tag-rua-not-configured"])
	}

	if len(dmarc.ruf) == 0 {
		dmarc.vulnerabilities = append(dmarc.vulnerabilities, vulns["tag-ruf-not-configured"])
	}

	if len(dmarc.pct) > 0 && dmarc.pct != "100" {
		vulnPCT := vulns["tag-pct-not-100"]
		dmarc.vulnerabilities = append(dmarc.vulnerabilities, vulnPCT)
	}

	if len(dmarc.adkim) > 0 && dmarc.adkim != "r" && dmarc.adkim != "s" {
		dmarc.vulnerabilities = append(dmarc.vulnerabilities, vulns["tag-adkim-not-valid"])
	}

	if len(dmarc.aspf) > 0 && dmarc.aspf != "r" && dmarc.aspf != "s" {
		dmarc.vulnerabilities = append(dmarc.vulnerabilities, vulns["tag-aspf-not-valid"])
	}

	if len(dmarc.sp) > 0 && dmarc.sp != "none" && dmarc.sp != "reject" && dmarc.sp != "quarantine" {
		dmarc.vulnerabilities = append(dmarc.vulnerabilities, vulns["tag-sp-not-valid"])
	}

	if len(dmarc.fo) > 0 && dmarc.fo != "0" && dmarc.fo != "1" && dmarc.fo != "d" && dmarc.fo != "s" {
		dmarc.vulnerabilities = append(dmarc.vulnerabilities, vulns["tag-fo-not-valid"])
	}

	if len(dmarc.rf) > 0 && dmarc.rf != "afrf" {
		dmarc.vulnerabilities = append(dmarc.vulnerabilities, vulns["tag-rf-not-valid"])
	}

	if len(dmarc.ri) > 0 {
		_, err := strconv.Atoi(dmarc.ri)
		if err != nil {
			dmarc.vulnerabilities = append(dmarc.vulnerabilities, vulns["tag-ri-not-valid"])
		}
	}

	if len(dmarc.rua) > 0 {
		dmarc.validateEmailList(dmarc.rua, "tag-rua-not-valid-mailto")
	}

	if len(dmarc.ruf) > 0 {
		dmarc.validateEmailList(dmarc.ruf, "tag-ruf-not-valid-mailto")
	}

}

func (dmarc *DMARC) validateEmailList(list, vulnerabilityName string) {
	emails := strings.Split(list, ",")
	for _, email := range emails {
		if strings.HasPrefix(email, "mailto:") {
			_, err := mail.ParseAddress(email[7:])
			if err != nil {
				dmarc.vulnerabilities = append(dmarc.vulnerabilities, vulns[vulnerabilityName])
				break
			}
		} else {
			dmarc.vulnerabilities = append(dmarc.vulnerabilities, vulns[vulnerabilityName])
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
				dmarc.vulnerabilities = append(dmarc.vulnerabilities, vulns["multiple-dmarc-found"])
				return false
			}

			foundDmarc = true
		}
	}

	if !foundDmarc && len(dmarc.vulnerabilities) == 0 {
		dmarc.vulnerabilities = append(dmarc.vulnerabilities, vulns["dmarc-not-found"])
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
		dmarc.vulnerabilities = append(dmarc.vulnerabilities, vulns["unable-to-parse-tags"])
		return false
	}

	if tagVersion != "v" {
		// the first tag is diferent than 'v', the spec requires the first field to be 'v'
		dmarc.vulnerabilities = append(dmarc.vulnerabilities, vulns["v-and-p-invalid-or-missing"])
		return false
	}

	if valueVersion != "DMARC1" {
		// the first tag is 'v' but the value is diferent than 'DMARC1' , the spec requires the version value to be set to 'DMARC1'
		dmarc.vulnerabilities = append(dmarc.vulnerabilities, vulns["tag-v-wrong-value"])
		return false
	}

	tagRequest, valueRequest, txtRecord, err := extractTagAndValue(txtRecord)
	if err != nil {
		// error trying to extract the second tag, score zero
		dmarc.vulnerabilities = append(dmarc.vulnerabilities, vulns["unable-to-parse-tags"])
		return false
	}

	isValidRequest := make(map[string]bool)
	isValidRequest["none"] = true
	isValidRequest["quarantine"] = true
	isValidRequest["reject"] = true

	if tagRequest != "p" {
		// the second tag is diferent than 'p' , the spec requires the second field to be 'v'
		dmarc.vulnerabilities = append(dmarc.vulnerabilities, vulns["v-and-p-invalid-or-missing"])
		return false
	}

	if !isValidRequest[valueRequest] {
		// the second tag is 'p' but the value is not a valid one [none, quarantine, reject]
		dmarc.vulnerabilities = append(dmarc.vulnerabilities, vulns["tag-p-wrong-value"])
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
			dmarc.vulnerabilities = append(dmarc.vulnerabilities, vulns["unable-to-parse-tags"])
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
