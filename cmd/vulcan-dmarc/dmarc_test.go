/*
Copyright 2021 Adevinta
*/

package main

import (
	"testing"
)

func TestDMARC_OK_1(t *testing.T) {
	txtRecords := []string{"v=DMARC1; p=reject"}

	dmarc := DMARC{}
	dmarc.parseTxtRecords(txtRecords)
	if len(dmarc.vulnerabilities) != 0 {
		t.Fatalf("wrong number of vulnerabilities found. Expected: 0, Got: %v", len(dmarc.vulnerabilities))
	}
}

func TestDMARC_OK_2(t *testing.T) {
	txtRecords := []string{"v=DMARC1; p   =         reject"}

	dmarc := DMARC{}
	dmarc.parseTxtRecords(txtRecords)
	if len(dmarc.vulnerabilities) != 0 {
		t.Fatalf("wrong number of vulnerabilities found. Expected: 0, Got: %v", len(dmarc.vulnerabilities))
	}
}

func TestDMARCNotFound(t *testing.T) {
	txtRecords := []string{}

	dmarc := DMARC{}
	dmarc.parseTxtRecords(txtRecords)
	if len(dmarc.vulnerabilities) != 1 {
		t.Fatalf("wrong number of vulnerabilities found. Expected: 1, Got: %v", len(dmarc.vulnerabilities))
	}

	expected := vulns["dmarc-not-found"].Description
	if dmarc.vulnerabilities[0].Description != expected {
		t.Fatalf("vulnerability expected: %v, Got: %v", expected, dmarc.vulnerabilities[0])
	}
}

func TestMultipleDMARCFound(t *testing.T) {
	txtRecords := []string{"v=DMARC1; p=reject", "v=DMARC1; p=none"}

	dmarc := DMARC{}
	dmarc.parseTxtRecords(txtRecords)
	if len(dmarc.vulnerabilities) != 1 {
		t.Fatalf("wrong number of vulnerabilities found. Expected: 1, Got: %v", len(dmarc.vulnerabilities))
	}

	expected := vulns["multiple-dmarc-found"].Description
	if dmarc.vulnerabilities[0].Description != expected {
		t.Fatalf("vulnerability expected: %v, Got: %v", expected, dmarc.vulnerabilities[0])
	}
}

func TestUnableToParseTags(t *testing.T) {
	txtRecords := []string{"v=DMARC1; p=reject; WRONGTAG"}

	dmarc := DMARC{}
	dmarc.parseTxtRecords(txtRecords)
	if len(dmarc.vulnerabilities) != 1 {
		t.Fatalf("wrong number of vulnerabilities found. Expected: 1, Got: %v", len(dmarc.vulnerabilities))
	}

	expected := vulns["unable-to-parse-tags"].Description
	if dmarc.vulnerabilities[0].Description != expected {
		t.Fatalf("vulnerability expected: %v, Got: %v", expected, dmarc.vulnerabilities[0])
	}
}

func TestVPTagsInvalidOrMissing(t *testing.T) {
	txtRecords := []string{"v=DMARC1; "}

	dmarc := DMARC{}
	dmarc.parseTxtRecords(txtRecords)
	if len(dmarc.vulnerabilities) != 1 {
		t.Fatalf("wrong number of vulnerabilities found. Expected: 1, Got: %v", len(dmarc.vulnerabilities))
	}

	expected := vulns["v-and-p-invalid-or-missing"].Description
	if dmarc.vulnerabilities[0].Description != expected {
		t.Fatalf("vulnerability expected: %v, Got: %v", expected, dmarc.vulnerabilities[0])
	}
}

func TestTag_V_WrongValue(t *testing.T) {
	txtRecords := []string{"v=DMARC1000; p=none;"}

	dmarc := DMARC{}
	dmarc.parseTxtRecords(txtRecords)
	if len(dmarc.vulnerabilities) != 1 {
		t.Fatalf("wrong number of vulnerabilities found. Expected: 1, Got: %v", len(dmarc.vulnerabilities))
	}

	expected := vulns["tag-v-wrong-value"].Description
	if dmarc.vulnerabilities[0].Description != expected {
		t.Fatalf("vulnerability expected: %v, Got: %v", expected, dmarc.vulnerabilities[0])
	}
}

func TestTag_P_WrongValue(t *testing.T) {
	txtRecords := []string{"v=DMARC1; p=SOMETHING;"}

	dmarc := DMARC{}
	dmarc.parseTxtRecords(txtRecords)
	if len(dmarc.vulnerabilities) != 1 {
		t.Fatalf("wrong number of vulnerabilities found. Expected: 1, Got: %v", len(dmarc.vulnerabilities))
	}

	expected := vulns["tag-p-wrong-value"].Description
	if dmarc.vulnerabilities[0].Description != expected {
		t.Fatalf("vulnerability expected: %v, Got: %v", expected, dmarc.vulnerabilities[0])
	}
}

func TestTag_P_IsNone(t *testing.T) {
	txtRecords := []string{"v=DMARC1; p=none;"}

	dmarc := DMARC{}
	dmarc.parseTxtRecords(txtRecords)
	dmarc.evaluate()

	expected := vulns["tag-p-is-none"].Description
	foundExpected := false
	for _, vulnerabilitiy := range dmarc.vulnerabilities {
		if vulnerabilitiy.Description == expected {
			foundExpected = true
		}
	}

	if !foundExpected {
		t.Fatalf("vulnerability expected but not found: %v", expected)
	}
}

func TestTag_P_IsQurantine(t *testing.T) {
	txtRecords := []string{"v=DMARC1; p=quarantine;"}

	dmarc := DMARC{}
	dmarc.parseTxtRecords(txtRecords)
	dmarc.evaluate()

	expected := vulns["tag-p-is-quarantine"].Description
	foundExpected := false
	for _, vulnerabilitiy := range dmarc.vulnerabilities {
		if vulnerabilitiy.Description == expected {
			foundExpected = true
		}
	}

	if !foundExpected {
		t.Fatalf("vulnerability expected but not found: %v", expected)
	}
}

func TestTag_RUA_NotConfigured(t *testing.T) {
	txtRecords := []string{"v=DMARC1; p=none;"}

	dmarc := DMARC{}
	dmarc.parseTxtRecords(txtRecords)
	dmarc.evaluate()

	expected := vulns["tag-rua-not-configured"].Description
	foundExpected := false
	for _, vulnerabilitiy := range dmarc.vulnerabilities {
		if vulnerabilitiy.Description == expected {
			foundExpected = true
		}
	}

	if !foundExpected {
		t.Fatalf("vulnerability expected but not found: %v", expected)
	}
}

func TestTag_RUA_Configured(t *testing.T) {
	txtRecords := []string{"v=DMARC1; p=none; rua=mailto:a@b.cde"}

	dmarc := DMARC{}
	dmarc.parseTxtRecords(txtRecords)
	dmarc.evaluate()

	notExpected := vulns["tag-rua-not-configured"].Description
	foundNotExpected := false
	for _, vulnerabilitiy := range dmarc.vulnerabilities {
		if vulnerabilitiy.Description == notExpected {
			foundNotExpected = true
		}
	}

	if foundNotExpected {
		t.Fatalf("vulnerability not expected: %v", notExpected)
	}
}

func TestTag_RUF_NotConfigured(t *testing.T) {
	txtRecords := []string{"v=DMARC1; p=none;"}

	dmarc := DMARC{}
	dmarc.parseTxtRecords(txtRecords)
	dmarc.evaluate()

	expected := vulns["tag-ruf-not-configured"].Description
	foundExpected := false
	for _, vulnerabilitiy := range dmarc.vulnerabilities {
		if vulnerabilitiy.Description == expected {
			foundExpected = true
		}
	}

	if !foundExpected {
		t.Fatalf("vulnerability expected but not found: %v", expected)
	}
}

func TestTag_RFA_Configured(t *testing.T) {
	txtRecords := []string{"v=DMARC1; p=none; ruf=mailto:a@b.cde"}

	dmarc := DMARC{}
	dmarc.parseTxtRecords(txtRecords)
	dmarc.evaluate()

	notExpected := vulns["tag-ruf-not-configured"].Description
	foundNotExpected := false
	for _, vulnerabilitiy := range dmarc.vulnerabilities {
		if vulnerabilitiy.Description == notExpected {
			foundNotExpected = true
		}
	}

	if foundNotExpected {
		t.Fatalf("vulnerability not expected: %v", notExpected)
	}
}

func TestTag_PCT_Not100(t *testing.T) {
	txtRecords := []string{"v=DMARC1; p=none; pct=50"}

	dmarc := DMARC{}
	dmarc.parseTxtRecords(txtRecords)
	dmarc.evaluate()

	expected := vulns["tag-pct-not-100"].Description
	foundExpected := false
	for _, vulnerabilitiy := range dmarc.vulnerabilities {
		if vulnerabilitiy.Description == expected {
			foundExpected = true
		}
	}

	if !foundExpected {
		t.Fatalf("vulnerability expected but not found: %v", expected)
	}
}

func TestTag_RUA_NotValidMailto(t *testing.T) {
	txtRecords := []string{"v=DMARC1; p=none; rua=mailto:a@b.cde,mailto:aaaaa"}

	dmarc := DMARC{}
	dmarc.parseTxtRecords(txtRecords)
	dmarc.evaluate()

	expected := vulns["tag-rua-not-valid-mailto"].Description
	foundExpected := false
	for _, vulnerabilitiy := range dmarc.vulnerabilities {
		if vulnerabilitiy.Description == expected {
			foundExpected = true
		}
	}

	if !foundExpected {
		t.Fatalf("vulnerability not expected: %v", expected)
	}
}

func TestTag_RUA_WithoutMailto(t *testing.T) {
	txtRecords := []string{"v=DMARC1; p=none; rua=mailto:a@b.cde,aaaaa"}

	dmarc := DMARC{}
	dmarc.parseTxtRecords(txtRecords)
	dmarc.evaluate()

	expected := vulns["tag-rua-not-valid-mailto"].Description
	foundExpected := false
	for _, vulnerabilitiy := range dmarc.vulnerabilities {
		if vulnerabilitiy.Description == expected {
			foundExpected = true
		}
	}

	if !foundExpected {
		t.Fatalf("vulnerability not expected: %v", expected)
	}
}

func TestTag_RUF_NotValidMailto(t *testing.T) {
	txtRecords := []string{"v=DMARC1; p=none; ruf=mailto:a@b.cde,mailto:aaaaa"}

	dmarc := DMARC{}
	dmarc.parseTxtRecords(txtRecords)
	dmarc.evaluate()

	expected := vulns["tag-ruf-not-valid-mailto"].Description
	foundExpected := false
	for _, vulnerabilitiy := range dmarc.vulnerabilities {
		if vulnerabilitiy.Description == expected {
			foundExpected = true
		}
	}

	if !foundExpected {
		t.Fatalf("vulnerability not expected: %v", expected)
	}
}

func TestTag_RUF_WithoutMailto(t *testing.T) {
	txtRecords := []string{"v=DMARC1; p=none; ruf=mailto:a@b.cde,aaaaa"}

	dmarc := DMARC{}
	dmarc.parseTxtRecords(txtRecords)
	dmarc.evaluate()

	expected := vulns["tag-ruf-not-valid-mailto"].Description
	foundExpected := false
	for _, vulnerabilitiy := range dmarc.vulnerabilities {
		if vulnerabilitiy.Description == expected {
			foundExpected = true
		}
	}

	if !foundExpected {
		t.Fatalf("vulnerability not expected: %v", expected)
	}
}

func TestTag_ADKIM_NotValid(t *testing.T) {
	txtRecords := []string{"v=DMARC1; p=none; adkim=xxxxx"}

	dmarc := DMARC{}
	dmarc.parseTxtRecords(txtRecords)
	dmarc.evaluate()

	expected := vulns["tag-adkim-not-valid"].Description
	foundExpected := false
	for _, vulnerabilitiy := range dmarc.vulnerabilities {
		if vulnerabilitiy.Description == expected {
			foundExpected = true
		}
	}

	if !foundExpected {
		t.Fatalf("vulnerability not expected: %v", expected)
	}
}

func TestTag_ASPF_NotValid(t *testing.T) {
	txtRecords := []string{"v=DMARC1; p=none; aspf=xxxxx"}

	dmarc := DMARC{}
	dmarc.parseTxtRecords(txtRecords)
	dmarc.evaluate()

	expected := vulns["tag-aspf-not-valid"].Description
	foundExpected := false
	for _, vulnerabilitiy := range dmarc.vulnerabilities {
		if vulnerabilitiy.Description == expected {
			foundExpected = true
		}
	}

	if !foundExpected {
		t.Fatalf("vulnerability expected but was not found: %v", expected)
	}
}

func TestTagSpNotValid(t *testing.T) {
	txtRecords := []string{"v=DMARC1; p=none; sp=xxxxx"}

	dmarc := DMARC{}
	dmarc.parseTxtRecords(txtRecords)
	dmarc.evaluate()

	expected := vulns["tag-sp-not-valid"].Description
	foundExpected := false
	for _, vulnerabilitiy := range dmarc.vulnerabilities {
		if vulnerabilitiy.Description == expected {
			foundExpected = true
		}
	}

	if !foundExpected {
		t.Fatalf("vulnerability expected but was not found: %v", expected)
	}
}

func TestTagFONotValid(t *testing.T) {
	txtRecords := []string{"v=DMARC1; p=none; fo=xxxxx"}

	dmarc := DMARC{}
	dmarc.parseTxtRecords(txtRecords)
	dmarc.evaluate()

	expected := vulns["tag-fo-not-valid"].Description
	foundExpected := false
	for _, vulnerabilitiy := range dmarc.vulnerabilities {
		if vulnerabilitiy.Description == expected {
			foundExpected = true
		}
	}

	if !foundExpected {
		t.Fatalf("vulnerability expected but was not found: %v", expected)
	}
}

func TestTagRFNotValid(t *testing.T) {
	txtRecords := []string{"v=DMARC1; p=none; rf=xxxxx"}

	dmarc := DMARC{}
	dmarc.parseTxtRecords(txtRecords)
	dmarc.evaluate()

	expected := vulns["tag-rf-not-valid"].Description
	foundExpected := false
	for _, vulnerabilitiy := range dmarc.vulnerabilities {
		if vulnerabilitiy.Description == expected {
			foundExpected = true
		}
	}

	if !foundExpected {
		t.Fatalf("vulnerability expected but was not found: %v", expected)
	}
}

func TestTagRFIsValid(t *testing.T) {
	txtRecords := []string{"v=DMARC1; p=none; rf=r"}

	dmarc := DMARC{}
	dmarc.parseTxtRecords(txtRecords)
	dmarc.evaluate()

	notExpected := vulns["tag-rf-not-valid"].Description
	foundNotExpected := false
	for _, vulnerabilitiy := range dmarc.vulnerabilities {
		if vulnerabilitiy.Description == notExpected {
			foundNotExpected = true
		}
	}

	if !foundNotExpected {
		t.Fatalf("vulnerability not expected but found: %v", notExpected)
	}
}

func TestTagRINotValid(t *testing.T) {
	txtRecords := []string{"v=DMARC1; p=none; ri=xxxxx"}

	dmarc := DMARC{}
	dmarc.parseTxtRecords(txtRecords)
	dmarc.evaluate()

	expected := vulns["tag-ri-not-valid"].Description
	foundExpected := false
	for _, vulnerabilitiy := range dmarc.vulnerabilities {
		if vulnerabilitiy.Description == expected {
			foundExpected = true
		}
	}

	if !foundExpected {
		t.Fatalf("vulnerability expected but was not found: %v", expected)
	}
}

func TestTagRIIsValid(t *testing.T) {
	txtRecords := []string{"v=DMARC1; p=none; ri=300"}

	dmarc := DMARC{}
	dmarc.parseTxtRecords(txtRecords)
	dmarc.evaluate()

	notExpected := vulns["tag-ri-not-valid"].Description
	foundNotExpected := false
	for _, vulnerabilitiy := range dmarc.vulnerabilities {
		if vulnerabilitiy.Description == notExpected {
			foundNotExpected = true
		}
	}

	if foundNotExpected {
		t.Fatalf("vulnerability not expected but found: %v", notExpected)
	}
}
