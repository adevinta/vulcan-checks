/*
Copyright 2019 Adevinta
*/

package main

import (
	"net"
	"strings"

	"github.com/adevinta/vulcan-report"
)

type spfField struct {
	field    string
	position int
}

// SPF represents a SPF record. All not parseable parts will be stored on
// UnknownOrInvalid array. problems field must be filled on evaluate method
type SPF struct {
	All              []spfField
	Include          []spfField
	A                []spfField
	Mx               []spfField
	Ptr              []spfField
	IP4              []spfField
	IP6              []spfField
	Exists           []spfField
	Redirect         []spfField
	Explanation      []spfField
	UnknownOrInvalid []spfField
	vulnerabilities  []report.Vulnerability
	numFields        int
}

const versionField = "v=spf1"

func (spf *SPF) countDNSLookUps() int {
	count := 0
	count += len(spf.Include)
	count += len(spf.A)
	count += len(spf.Mx)
	count += len(spf.Ptr) //dont follow
	count += len(spf.Exists)
	count += len(spf.Redirect)

	//parse includes
	for _, include := range spf.Include {
		if len(include.field) > len("include:") {
			includeURL := include.field[9:]
			spfInclude := SPF{}
			spfInclude.parse(includeURL)
			count = count + spfInclude.countDNSLookUps()
		}
	}

	return count
}

func (spf *SPF) evaluate() {
	if len(spf.All) == 0 && len(spf.Redirect) == 0 {
		//there is no `all`
		spf.vulnerabilities = append(spf.vulnerabilities, vulns["no-all-or-redirect"])
	}

	existsMechanismsAfterFirstAll := false
	var firstAll *spfField
	iFirst := spf.numFields
	for _, all := range spf.All {
		if all.position <= iFirst {
			firstAll = &all
			iFirst = all.position
		}
	}

	if iFirst < spf.numFields {
		existsMechanismsAfterFirstAll = true
	}

	if existsMechanismsAfterFirstAll {
		spf.vulnerabilities = append(spf.vulnerabilities, vulns["mechanisms-after-first-all-are-ignored"])
	}

	if firstAll != nil && firstAll.field[0] == '+' {
		spf.vulnerabilities = append(spf.vulnerabilities, vulns["all-configured-as-PASS"])
	}

	if firstAll != nil && firstAll.field[0] == '?' {
		spf.vulnerabilities = append(spf.vulnerabilities, vulns["all-configured-as-NEUTRAL"])
	}

	if firstAll != nil && firstAll.field[0] == '~' {
		spf.vulnerabilities = append(spf.vulnerabilities, vulns["all-configured-as-SOFTFAIL"])
	}

	if spf.countDNSLookUps() > 10 {
		spf.vulnerabilities = append(spf.vulnerabilities, vulns["dns-queries-exceeded-limit"])
	}

}

func (spf *SPF) parse(domain string) bool {
	//perform a TXT query on DNS
	records, _ := net.LookupTXT(domain)
	return spf.parseTxtRecords(records)
}

func (spf *SPF) parseTxtRecords(records []string) bool {
	rawSPF := ""
	foundSPF := false
	for _, record := range records {
		if strings.HasPrefix(record, versionField) {
			if foundSPF {
				// we should not have another SPF field
				spf.vulnerabilities = append(spf.vulnerabilities, vulns["multiple-spf-found"])
				return false
			}
			rawSPF = record
			foundSPF = true
		}
	}

	//no spf found
	if !foundSPF {
		spf.vulnerabilities = append(spf.vulnerabilities, vulns["spf-not-found"])
		return false
	}

	fields := strings.Split(rawSPF, " ")
	for i, field := range fields[1:] {
		// if it`s not an empty field
		if len(field) > 0 {
			// parse it!
			parseField(field, i+1, spf)
		}
	}
	return true
}

func parseField(field string, i int, spf *SPF) {
	spf.numFields++

	// look for the qualifier, if it`s not there then we assume the default one '+'
	qualifier := '+'
	if len(field) > 0 {
		if field[0] == '+' || field[0] == '-' || field[0] == '?' || field[0] == '~' {
			qualifier = rune(field[0])
			field = field[1:]
		}
	}
	qualifierStr := string(qualifier)

	//after that it`s just a matter of comparin fields and filling the spf struct
	if field == "all" {
		spf.All = append(spf.All, spfField{field: qualifierStr + field, position: i})
		return
	}

	if strings.HasPrefix(field, "include:") && len(field) > len("include:") {
		spf.Include = append(spf.Include, spfField{field: qualifierStr + field, position: i})
		return
	}

	if validateMechanism(field, "mx") {
		spf.Mx = append(spf.Mx, spfField{field: qualifierStr + field, position: i})
		return
	}

	if validateMechanism(field, "a") {
		spf.A = append(spf.A, spfField{field: qualifierStr + field, position: i})
		return
	}

	if validateMechanism(field, "ptr") {
		spf.Ptr = append(spf.Ptr, spfField{field: qualifierStr + field, position: i})
		return
	}

	if validateMechanism(field, "ip4") {
		spf.IP4 = append(spf.IP4, spfField{field: qualifierStr + field, position: i})
		return
	}

	if validateMechanism(field, "ip6") {
		spf.IP6 = append(spf.IP6, spfField{field: qualifierStr + field, position: i})
		return
	}

	if validateMechanism(field, "exists") {
		spf.Exists = append(spf.Exists, spfField{field: qualifierStr + field, position: i})
		return
	}

	if validateModifier(field, "redirect") {
		spf.Redirect = append(spf.Redirect, spfField{field: qualifierStr + field, position: i})
		return
	}

	if validateModifier(field, "exp") {
		spf.Explanation = append(spf.Explanation, spfField{field: qualifierStr + field, position: i})
		return
	}

	// Unknown
	spf.UnknownOrInvalid = append(spf.UnknownOrInvalid, spfField{field: qualifierStr + field, position: i})
}

//mechanisms are separated by ':'
func validateMechanism(field, mechanism string) bool {
	return field == mechanism || (strings.HasPrefix(field, mechanism+":") && len(field) > len(mechanism+":"))
}

//modifiers are separated by '='
func validateModifier(field, modifier string) bool {
	return field == modifier || (strings.HasPrefix(field, modifier+"=") && len(field) > len(modifier+"="))
}
