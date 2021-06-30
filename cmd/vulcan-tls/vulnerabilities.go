/*
Copyright 2019 Adevinta
*/

package main

import report "github.com/adevinta/vulcan-report"

var (
	weakCiphersuitesVulnerability = report.Vulnerability{
		Summary:     "Weak SSL/TLS Ciphersuites",
		Description: "This site supports one or more SSL/TLS ciphersuites with known security weaknesses.",
		Labels:      []string{"issue", "ssl"},
		CWEID:       326,
		Recommendations: []string{
			"Consider client compatibility before remediating this vulnerability",
			"Disable support for the weak ciphersuites in your SSL/TLS terminator",
			"Use the Mozilla tool in the resources easily to generate a strong configuration",
		},
		References: []string{
			"https://wiki.mozilla.org/Security/Server_Side_TLS",
			"https://mozilla.github.io/server-side-tls/ssl-config-generator/",
		},
	}

	weakProtocolsVulnerability = report.Vulnerability{
		Summary:     "Weak SSL/TLS Protocol Versions",
		Description: "This site supports one or more SSL/TLS protocol versions with known security weakenesses.",
		Labels:      []string{"issue", "ssl"},
		CWEID:       326,
		Recommendations: []string{
			"Consider client compatibility before remediating this vulnerability",
			"Disable support for the weak protocol versions in your SSL/TLS terminator",
			"Use the Mozilla tool in the resources to easily generate a strong configuration",
		},
		References: []string{
			"https://wiki.mozilla.org/Security/Server_Side_TLS",
			"https://mozilla.github.io/server-side-tls/ssl-config-generator/",
		},
	}

	missingProtocolsVulnerability = report.Vulnerability{
		Summary:     "Missing Strong SSL/TLS Protocol Versions",
		Description: "This site does not support one or more SSL/TLS protocol versions considered to be strong.",
		Labels:      []string{"issue", "ssl"},
		CWEID:       326,
		Recommendations: []string{
			"Enable support for the strong SSL/TLS protocol versions in your SSL/TLS terminator",
			"Use the Mozilla tool in the resources to easily generate a strong configuration",
		},
		References: []string{
			"https://wiki.mozilla.org/Security/Server_Side_TLS",
			"https://mozilla.github.io/server-side-tls/ssl-config-generator/",
		},
	}

	defaultVulnerability = report.Vulnerability{
		Score:      report.SeverityThresholdLow,
		Labels:     []string{"issue", "ssl"},
		CWEID:      326,
		References: []string{"https://wiki.mozilla.org/Security/Server_Side_TLS"},
	}
)
