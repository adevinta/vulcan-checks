/*
Copyright 2021 Adevinta
*/

package main

import (
	"encoding/json"
)

type observatoryResult struct {
	Error string `json:"error"`
	Scan  struct {
		Grade               string            `json:"grade"`
		LikelihoodIndicator string            `json:"likelihood_indicator"`
		ResponseHeaders     map[string]string `json:"response_headers"`
		Score               int               `json:"score"`
		TestsFailed         int               `json:"tests_failed"`
		TestsPassed         int               `json:"tests_passed"`
		TestsQuantity       int               `json:"tests_quantity"`
	} `json:"scan"`
	Tests struct {
		ContentSecurityPolicy struct {
			Data             json.RawMessage `json:"data"`
			Expectation      string          `json:"expectation"`
			HTTP             bool            `json:"http"`
			Meta             bool            `json:"meta"`
			Pass             bool            `json:"pass"`
			Policy           json.RawMessage `json:"policy"`
			Result           string          `json:"result"`
			ScoreDescription string          `json:"score_description"`
			ScoreModifier    int             `json:"score_modifier"`
		} `json:"content-security-policy"`
		Contribute struct {
			Data             json.RawMessage `json:"data"`
			Expectation      string          `json:"expectation"`
			Pass             bool            `json:"pass"`
			Result           string          `json:"result"`
			ScoreDescription string          `json:"score_description"`
			ScoreModifier    int             `json:"score_modifier"`
		} `json:"contribute"`
		Cookies struct {
			Data             json.RawMessage `json:"data"`
			Expectation      string          `json:"expectation"`
			Pass             bool            `json:"pass"`
			Result           string          `json:"result"`
			ScoreDescription string          `json:"score_description"`
			ScoreModifier    int             `json:"score_modifier"`
		} `json:"cookies"`
		CrossOriginResourceSharing struct {
			Data             json.RawMessage `json:"data"`
			Expectation      string          `json:"expectation"`
			Pass             bool            `json:"pass"`
			Result           string          `json:"result"`
			ScoreDescription string          `json:"score_description"`
			ScoreModifier    int             `json:"score_modifier"`
		} `json:"cross-origin-resource-sharing"`
		PublicKeyPinning struct {
			Data              json.RawMessage `json:"data"`
			Expectation       string          `json:"expectation"`
			IncludeSubDomains bool            `json:"includeSubDomains"`
			MaxAge            int             `json:"max-age"`
			NumPins           int             `json:"numPins"`
			Pass              bool            `json:"pass"`
			Preloaded         bool            `json:"preloaded"`
			Result            string          `json:"result"`
			ScoreDescription  string          `json:"score_description"`
			ScoreModifier     int             `json:"score_modifier"`
		} `json:"public-key-pinning"`
		Redirection struct {
			Destination      string          `json:"destination"`
			Expectation      string          `json:"expectation"`
			Pass             bool            `json:"pass"`
			Redirects        bool            `json:"redirects"`
			Result           string          `json:"result"`
			Route            json.RawMessage `json:"route"`
			ScoreDescription string          `json:"score_description"`
			ScoreModifier    int             `json:"score_modifier"`
			StatusCode       int             `json:"status_code"`
		} `json:"redirection"`
		ReferrerPolicy struct {
			Data             json.RawMessage `json:"data"`
			Expectation      string          `json:"expectation"`
			HTTP             bool            `json:"http"`
			Meta             bool            `json:"meta"`
			Pass             bool            `json:"pass"`
			Result           string          `json:"result"`
			ScoreDescription string          `json:"score_description"`
			ScoreModifier    int             `json:"score_modifier"`
		} `json:"referrer-policy"`
		StrictTransportSecurity struct {
			Data              json.RawMessage `json:"data"`
			Expectation       string          `json:"expectation"`
			IncludeSubDomains bool            `json:"includeSubDomains"`
			MaxAge            int             `json:"max-age"`
			Pass              bool            `json:"pass"`
			Preload           bool            `json:"preload"`
			Preloaded         bool            `json:"preloaded"`
			Result            string          `json:"result"`
			ScoreDescription  string          `json:"score_description"`
			ScoreModifier     int             `json:"score_modifier"`
		} `json:"strict-transport-security"`
		SubresourceIntegrity struct {
			Data             json.RawMessage `json:"data"`
			Expectation      string          `json:"expectation"`
			Pass             bool            `json:"pass"`
			Result           string          `json:"result"`
			ScoreDescription string          `json:"score_description"`
			ScoreModifier    int             `json:"score_modifier"`
		} `json:"subresource-integrity"`
		XContentTypeOptions struct {
			Expectation      string `json:"expectation"`
			Pass             bool   `json:"pass"`
			Result           string `json:"result"`
			ScoreDescription string `json:"score_description"`
			ScoreModifier    int    `json:"score_modifier"`
		} `json:"x-content-type-options"`
		XFrameOptions struct {
			Data             json.RawMessage `json:"data"`
			Expectation      string          `json:"expectation"`
			Pass             bool            `json:"pass"`
			Result           string          `json:"result"`
			ScoreDescription string          `json:"score_description"`
			ScoreModifier    int             `json:"score_modifier"`
		} `json:"x-frame-options"`
		XXSSProtection struct {
			Data             json.RawMessage `json:"data"`
			Expectation      string          `json:"expectation"`
			Pass             bool            `json:"pass"`
			Result           string          `json:"result"`
			ScoreDescription string          `json:"score_description"`
			ScoreModifier    int             `json:"score_modifier"`
		} `json:"x-xss-protection"`
	} `json:"tests"`
}

type observatoryScanner struct {
	output []byte
}

func (s *observatoryScanner) ProcessOutputChunk(chunk []byte) bool {
	s.output = append(s.output, chunk...)
	return true
}
