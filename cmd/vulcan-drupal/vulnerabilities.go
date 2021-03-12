/*
Copyright 2021 Adevinta
*/

package main

import report "github.com/adevinta/vulcan-report"

type drupalVulnerability struct {
	Constraints   []string // Constraints that vulnerable versions must meet.
	Vulnerability report.Vulnerability
}

var (
	infoDrupal = report.Vulnerability{
		Summary:     "Drupal Detected",
		Description: "The Drupal CMS has been detected.",
		Score:       report.SeverityThresholdNone,
	}

	recommendations = []string{
		"Make sure your Drupal version is updated",
		"If you are running Drupal 8.6.x, upgrade to Drupal 8.6.6",
		"If you are running an earlier Drupal 8.x, upgrade to Drupal 8.5.11",
		"If you are running Drupal 7.x or earlier, upgrade to Drupal 7.62",
	}

	drupalVulnerabilities = []drupalVulnerability{
		drupalVulnerability{
			Constraints: []string{"<7", ">=8,<8.5"},
			Vulnerability: report.Vulnerability{
				Summary:         "Drupal - End-of-Life",
				CWEID:           937,
				Description:     "Versions of Drupal 8 prior to 8.5 and versions prior to 7 are end-of-life and do not receive security coverage.",
				Score:           report.SeverityThresholdCritical,
				Recommendations: []string{"Update to a supported version"},
			},
		},
		drupalVulnerability{
			Constraints: []string{">=7,<8", ">=8,<8.5.11", ">=8.6,<8.6.10"},
			Vulnerability: report.Vulnerability{
				Summary:         "Drupal - SA-CORE-2019-003 - Remote Code Execution",
				CWEID:           937,
				Description:     "Some field types do not properly sanitize data from non-form sources. This can lead to arbitrary PHP code execution in some cases.",
				Score:           report.SeverityThresholdCritical,
				References:      []string{"https://www.drupal.org/sa-core-2019-003"},
				Recommendations: append(recommendations, "Be sure to install any available security updates for contributed projects after updating Drupal core."),
			},
		},
		drupalVulnerability{
			Constraints: []string{">=7,<7.62", ">=8,<8.5.9", ">=8.6,<8.6.6"},
			Vulnerability: report.Vulnerability{
				Summary:         "Drupal - SA-CORE-2019-002 - Arbitrary PHP code execution",
				CWEID:           937,
				Description:     "A remote code execution vulnerability exists in PHP's built-in phar stream wrapper when performing file operations on an untrusted phar:// URI.\n\nSome Drupal code (core, contrib, and custom) may be performing file operations on insufficiently validated user input, thereby being exposed to this vulnerability.\n\nThis vulnerability is mitigated by the fact that such code paths typically require access to an administrative permission or an atypical configuration.",
				Score:           report.SeverityThresholdHigh,
				References:      []string{"https://www.drupal.org/sa-core-2019-002"},
				Recommendations: recommendations,
			},
		},
		drupalVulnerability{
			Constraints: []string{">=7,<7.62", ">=8,<8.5.9", ">=8.6,<8.6.6"},
			Vulnerability: report.Vulnerability{
				Summary:         "Drupal - SA-CORE-2019-001 - Third Party Libraries",
				CWEID:           937,
				Description:     "Drupal core uses the third-party PEAR Archive_Tar library. This library has released a security update which impacts some Drupal configurations. Refer to CVE-2018-1000888 for details.",
				Score:           report.SeverityThresholdHigh,
				References:      []string{"https://www.drupal.org/sa-core-2019-001"},
				Recommendations: recommendations,
			},
		},
		drupalVulnerability{
			Constraints: []string{">=7,<7.60", ">=8,<8.5.8", ">=8.6,<8.6.2"},
			Vulnerability: report.Vulnerability{
				Summary:         "Drupal - SA-CORE-2018-006 - Multiple Vulnerabilities",
				CWEID:           937,
				Description:     "Multiple vulnerabilities in both Drupal 7 and Drupal 8, one critical",
				Score:           report.SeverityThresholdHigh,
				References:      []string{"https://www.drupal.org/sa-core-2018-006"},
				Recommendations: recommendations,
			},
		},
		drupalVulnerability{
			Constraints: []string{">=8,<8.5.6"},
			Vulnerability: report.Vulnerability{
				Summary:         "Drupal - SA-CORE-2018-005 - 3rd-party libraries",
				CWEID:           937,
				Description:     "If Symfony is used, path restrictions can be bypassed",
				Score:           report.SeverityThresholdLow,
				References:      []string{"https://www.drupal.org/sa-core-2018-005"},
				Recommendations: recommendations,
			},
		},
		drupalVulnerability{
			Constraints: []string{">=7,<7.59", ">=8,<8.4.8", ">=8.5,<8.5.3"},
			Vulnerability: report.Vulnerability{
				Summary:         "Drupal - SA-CORE-2018-004 - Remote Code Execution",
				CWEID:           937,
				Description:     "A remote code execution vulnerability exists within multiple subsystems of Drupal 7.x and 8.x. This potentially allows attackers to exploit multiple attack vectors on a Drupal site, which could result in the site being compromised. This vulnerability is related to Drupal core - Highly critical - Remote Code Execution - SA-CORE-2018-002. Both SA-CORE-2018-002 and this vulnerability are being exploited in the wild.",
				Score:           report.SeverityThresholdCritical,
				References:      []string{"https://www.drupal.org/sa-core-2018-004"},
				Recommendations: recommendations,
			},
		},
		drupalVulnerability{
			Constraints: []string{">=8,<8.5.2"},
			Vulnerability: report.Vulnerability{
				Summary:         "Drupal - SA-CORE-2018-003 - Cross-Site Scripting",
				CWEID:           937,
				Description:     "CKEditor, a third-party JavaScript library included in Drupal core, has a cross-site scripting (XSS) vulnerability. The vulnerability stems from the fact that it was possible to execute XSS inside CKEditor when using the image2 plugin (which Drupal 8 core also uses).",
				Score:           report.SeverityThresholdHigh,
				References:      []string{"https://www.drupal.org/sa-core-2018-003"},
				Recommendations: recommendations,
			},
		},
		drupalVulnerability{
			Constraints: []string{"<7.58", ">=8,<8.3.9", ">=8.4,<8.4.6", ">=8.5,<8.5.1"},
			Vulnerability: report.Vulnerability{
				Summary:         "Drupal - SA-CORE-2018-002 - Remote Code Execution",
				CWEID:           937,
				Description:     "A remote code execution vulnerability exists within multiple subsystems of Drupal 7.x and 8.x. This potentially allows attackers to exploit multiple attack vectors on a Drupal site, which could result in the site being completely compromised.",
				Score:           report.SeverityThresholdCritical,
				References:      []string{"https://www.drupal.org/sa-core-2018-002"},
				Recommendations: recommendations,
			},
		},
		drupalVulnerability{
			Constraints: []string{">=7,<7.57", ">=8,<8.4.5"},
			Vulnerability: report.Vulnerability{
				Summary:         "Drupal - SA-CORE-2018-001 - Multiple Vulnerabilities",
				CWEID:           937,
				Description:     "Multiple critical vulnerabilities in both Drupal 7 and Drupal 8.",
				Score:           report.SeverityThresholdCritical,
				References:      []string{"https://www.drupal.org/sa-core-2018-001"},
				Recommendations: recommendations,
			},
		},
	}
)
