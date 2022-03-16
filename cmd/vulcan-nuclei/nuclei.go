package main

import "time"

type Info struct {
	Name           string            `json:"name,omitempty"`
	Description    string            `json:"description,omitempty"`
	Metadata       map[string]string `json:"metadata,omitempty"`
	Reference      []string          `json:"reference,omitempty"`
	Tags           []string          `json:"tags,omitempty"`
	Remediation    string            `json:"remediation,omitempty"`
	Severity       string            `json:"severity,omitempty"`
	Classification Classification    `json:"classification,omitempty"`
}

type ResultEvent struct {
	Template         string                 `json:"template,omitempty"`
	TemplateURL      string                 `json:"template-url,omitempty"`
	TemplateID       string                 `json:"template-id,omitempty"`
	Info             Info                   `json:"info,omitempty"`
	MatcherName      string                 `json:"matcher-name,omitempty"`
	ExtractorName    string                 `json:"extractor-name,omitempty"`
	Type             string                 `json:"type,omitempty"`
	Host             string                 `json:"host,omitempty"`
	Path             string                 `json:"path,omitempty"`
	Matched          string                 `json:"matched-at,omitempty"`
	ExtractedResults []string               `json:"extracted-results,omitempty"`
	Request          string                 `json:"request,omitempty"`
	Response         string                 `json:"response,omitempty"`
	Metadata         map[string]interface{} `json:"meta,omitempty"`
	IP               string                 `json:"ip,omitempty"`
	Timestamp        time.Time              `json:"timestamp,omitempty"`
	CURLCommand      string                 `json:"curl-command,omitempty"`
	MatcherStatus    bool                   `json:"matcher-status,omitempty"`
}

type Classification struct {
	CVEID       []string `json:"cve-id,omitempty"`
	CWEID       []string `json:"cwe-id,omitempty"`
	CVSSMetrics string   `json:"cvss-metrics,omitempty"`
	CVSSScore   float64  `json:"cvss-score,omitempty"`
}
