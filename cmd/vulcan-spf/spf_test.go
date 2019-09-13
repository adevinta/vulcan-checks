package main

import (
	"testing"
)

func TestSPF_OK_1(t *testing.T) {
	txtRecords := []string{"v=spf1; "}

	spf := SPF{}
	spf.parseTxtRecords(txtRecords)
	if len(spf.vulnerabilities) != 0 {
		t.Fatalf("wrong number of vulnerabilities found. Expected: 0, Got: %v", len(spf.vulnerabilities))
	}
}

func TestSPF_MechanismsAfterFirstAll_AreIgnored(t *testing.T) {
	txtRecords := []string{"v=spf1 -all mx"}

	spf := SPF{}
	spf.parseTxtRecords(txtRecords)
	spf.countDNSLookUps()
	spf.evaluate()
	if len(spf.vulnerabilities) != 1 {
		t.Fatalf("wrong number of vulnerabilities found. Expected: 1, Got: %v", len(spf.vulnerabilities))
	}

	expected := vulns["mechanisms-after-first-all-are-ignored"].Description
	if spf.vulnerabilities[0].Description != expected {
		t.Fatalf("vulnerability expected: %v, Got: %v", expected, spf.vulnerabilities[0])
	}
}

func TestSPF_NoAllOrRedirect(t *testing.T) {
	txtRecords := []string{"v=spf1"}

	spf := SPF{}
	spf.parseTxtRecords(txtRecords)
	spf.countDNSLookUps()
	spf.evaluate()

	expected := vulns["no-all-or-redirect"].Description
	foundExpected := false
	for _, vulnerabilitiy := range spf.vulnerabilities {
		if vulnerabilitiy.Description == expected {
			foundExpected = true
		}
	}

	if !foundExpected {
		t.Fatalf("vulnerability expected but not found: %v", expected)
	}
}

func TestSPF_AllConfiguredAsPass(t *testing.T) {
	txtRecords := []string{"v=spf1 +all"}

	spf := SPF{}
	spf.parseTxtRecords(txtRecords)
	spf.countDNSLookUps()
	spf.evaluate()

	expected := vulns["all-configured-as-PASS"].Description
	foundExpected := false
	for _, vulnerabilitiy := range spf.vulnerabilities {
		if vulnerabilitiy.Description == expected {
			foundExpected = true
		}
	}

	if !foundExpected {
		t.Fatalf("vulnerability expected but not found: %v", expected)
	}
}

func TestSPF_AllConfiguredAsNeutral(t *testing.T) {
	txtRecords := []string{"v=spf1 ?all"}

	spf := SPF{}
	spf.parseTxtRecords(txtRecords)
	spf.countDNSLookUps()
	spf.evaluate()

	expected := vulns["all-configured-as-NEUTRAL"].Description
	foundExpected := false
	for _, vulnerabilitiy := range spf.vulnerabilities {
		if vulnerabilitiy.Description == expected {
			foundExpected = true
		}
	}

	if !foundExpected {
		t.Fatalf("vulnerability expected but not found: %v", expected)
	}
}

func TestSPF_AllConfiguredAsSOFTFAIL(t *testing.T) {
	txtRecords := []string{"v=spf1 ~all"}

	spf := SPF{}
	spf.parseTxtRecords(txtRecords)
	spf.countDNSLookUps()
	spf.evaluate()

	expected := vulns["all-configured-as-SOFTFAIL"].Description
	foundExpected := false
	for _, vulnerabilitiy := range spf.vulnerabilities {
		if vulnerabilitiy.Description == expected {
			foundExpected = true
		}
	}

	if !foundExpected {
		t.Fatalf("vulnerability expected but not found: %v", expected)
	}
}

func TestSPF_DNS_QueriesExceededLimit(t *testing.T) {
	txtRecords := []string{"v=spf1 include:_spf.google.com include:_spf.google.com include:_spf.google.com include:_spf.google.com  ~all"}

	spf := SPF{}
	spf.parseTxtRecords(txtRecords)
	spf.countDNSLookUps()
	spf.evaluate()

	expected := vulns["dns-queries-exceeded-limit"].Description
	foundExpected := false
	for _, vulnerabilitiy := range spf.vulnerabilities {
		if vulnerabilitiy.Description == expected {
			foundExpected = true
		}
	}

	if !foundExpected {
		t.Fatalf("vulnerability expected but not found: %v", expected)
	}
}

func TestSPF_MultipleSPFFound(t *testing.T) {
	txtRecords := []string{
		"v=spf1 ~all",
		"v=spf1 ~all"}

	spf := SPF{}
	spf.parseTxtRecords(txtRecords)
	spf.countDNSLookUps()
	spf.evaluate()

	expected := vulns["multiple-spf-found"].Description
	foundExpected := false
	for _, vulnerabilitiy := range spf.vulnerabilities {
		if vulnerabilitiy.Description == expected {
			foundExpected = true
		}
	}

	if !foundExpected {
		t.Fatalf("vulnerability expected but not found: %v", expected)
	}
}

func TestSPF_NoSPFFound(t *testing.T) {
	txtRecords := []string{}

	spf := SPF{}
	spf.parseTxtRecords(txtRecords)
	spf.countDNSLookUps()
	spf.evaluate()

	expected := vulns["spf-not-found"].Description
	foundExpected := false
	for _, vulnerabilitiy := range spf.vulnerabilities {
		if vulnerabilitiy.Description == expected {
			foundExpected = true
		}
	}

	if !foundExpected {
		t.Fatalf("vulnerability expected but not found: %v", expected)
	}
}
