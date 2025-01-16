/*
Copyright 2025 Adevinta
*/

package main

import (
	"strings"
	"testing"
	"text/template"
)

func TestTemplate(t *testing.T) {
	if strings.Contains(configTemplate, "\t") {
		t.Errorf("template contains tabs: %s", strings.ReplaceAll(configTemplate, "\t", "***"))
	}

	tmpl, err := template.New("config").Parse(configTemplate)
	if err != nil {
		panic(err)
	}

	tests := []struct {
		name            string
		opts            tmplOptions
		wantContains    []string
		wantNotContains []string
	}{
		{
			name: "Simple",
			opts: tmplOptions{
				URL: "http://my.url",
				Dir: "/tmp",
			},
			wantContains: []string{
				"maxDuration: 0",
				`reportDir: "/tmp"`,
				`r: "/tmp"`,
				`urls: [ "http://my.url" ]`,
				`includePaths: [ "http://my.url/.*" ]`,
			},
			wantNotContains: []string{
				"credentials:",
				"type: openapi",
				"type: activeScan",
				"maxDuration: 10",
			},
		},
		{
			name: "Active",
			opts: tmplOptions{
				Opts: options{
					Active: true,
				}},
			wantContains: []string{
				"type: activeScan",
			},
		},
		{
			name: "Openapi",
			opts: tmplOptions{
				Opts: options{OpenapiUrl: "http://my.url/openapi"},
			},
			wantContains: []string{
				"apiUrl: \"http://my.url/openapi\"",
			},
		},
		{
			name: "Constants",
			opts: tmplOptions{
				Opts: options{
					Active:            true,
					MaxSpiderDuration: 10,
					MaxRuleDuration:   100,
					MaxScanDuration:   1000,
				},
			},
			wantContains: []string{
				"maxDuration: 10",
				"maxRuleDurationInMins: 100",
				"maxScanDurationInMins: 1000",
			},
		},
		{
			name: "DisabledScanners",
			opts: tmplOptions{
				Opts: options{
					DisabledScanners: []string{"S1", "123"},
				},
			},
			wantContains: []string{
				"- id: S1",
				"- id: 123",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sb := new(strings.Builder)
			err = tmpl.Execute(sb, tt.opts)
			if err != nil {
				t.Errorf("error: %v", err)
			}
			for _, sub := range tt.wantContains {
				if !strings.Contains(sb.String(), sub) {
					t.Errorf("not contains: %s vs %s", sb.String(), sub)
				}
			}
			for _, sub := range tt.wantNotContains {
				if strings.Contains(sb.String(), sub) {
					t.Errorf("contains: %s vs %s", sb.String(), sub)
				}
			}
		})
	}
}
