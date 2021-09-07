/*
Copyright 2019 Adevinta
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
				Recommendations: []string{
					"If you are using Drupal 8.6.x, upgrade to Drupal 8.6.10.",
					"If you are using Drupal 8.5.x or earlier, upgrade to Drupal 8.5.11.",
					"Be sure to install any available security updates for contributed projects after updating Drupal core.",
					"No core update is required for Drupal 7, but several Drupal 7 contributed modules do require updates, see https://www.drupal.org/security/contrib .",
					"Versions of Drupal 8 prior to 8.5.x are end-of-life and do not receive security coverage.",
				},
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
				Recommendations: []string{
					"If you are using Drupal 8.6.x, upgrade to Drupal 8.6.6.",
					"If you are using Drupal 8.5.x or earlier, upgrade to Drupal 8.5.9.",
					"If you are using Drupal 7.x, upgrade to Drupal 7.62.",
					"Versions of Drupal 8 prior to 8.5.x are end-of-life and do not receive security coverage.",
				},
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
				Recommendations: []string{
					"If you are using Drupal 8.6.x, upgrade to Drupal 8.6.6.",
					"If you are using Drupal 8.5.x or earlier, upgrade to Drupal 8.5.9.",
					"If you are using Drupal 7.x, upgrade to Drupal 7.62.",
					"Versions of Drupal 8 prior to 8.5.x are end-of-life and do not receive security coverage.",
				},
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
				Recommendations: []string{
					"Upgrade to the most recent version of Drupal 7 or 8 core.",
					"If you are running 7.x, upgrade to Drupal 7.60.",
					"If you are running 8.6.x, upgrade to Drupal 8.6.2.",
					"If you are running 8.5.x or earlier, upgrade to Drupal 8.5.8.",
					"Minor versions of Drupal 8 prior to 8.5.x are not supported and do not receive security coverage, so sites running older versions should update to the above 8.5.x release immediately. 8.5.x will receive security coverage until May 2019.",
				},
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
				Recommendations: []string{
					"Upgrade to Drupal 8.5.6.",
					"Versions of Drupal 8 prior to 8.5.x are end-of-life and do not receive security coverage.",
				},
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
				Recommendations: []string{
					"Upgrade to the most recent version of Drupal 7 or 8 core.",
					"If you are running 7.x, upgrade to Drupal 7.59.",
					"If you are running 8.5.x, upgrade to Drupal 8.5.3.",
					"If you are running 8.4.x, upgrade to Drupal 8.4.8. (Drupal 8.4.x is no longer supported and we don't normally provide security releases for unsupported minor releases. However, we are providing this 8.4.x release so that sites can update as quickly as possible. You should update to 8.4.8 immediately, then update to 8.5.3 or the latest secure release as soon as possible.)",
				},
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
				Recommendations: []string{
					"If you are using Drupal 8, update to Drupal 8.5.2 or Drupal 8.4.7.",
					"The Drupal 7.x CKEditor contributed module is not affected if you are running CKEditor module 7.x-1.18 and using CKEditor from the CDN, since it currently uses a version of the CKEditor library that is not vulnerable.",
					"If you installed CKEditor in Drupal 7 using another method (for example with the WYSIWYG module or the CKEditor module with CKEditor locally) and you’re using a version of CKEditor from 4.5.11 up to 4.9.1, update the third-party JavaScript library by downloading CKEditor 4.9.2 from CKEditor's site.",
				},
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
				Recommendations: []string{
					"Upgrade to the most recent version of Drupal 7 or 8 core.",
					"If you are running 7.x, upgrade to Drupal 7.58.",
					"If you are running 8.5.x, upgrade to Drupal 8.5.1.",
					"Drupal 8.3.x and 8.4.x are no longer supported and we don't normally provide security releases for unsupported minor releases. However, given the potential severity of this issue, we are providing 8.3.x and 8.4.x releases that includes the fix for sites which have not yet had a chance to update to 8.5.0.",
					"Your site's update report page will recommend the 8.5.x release even if you are on 8.3.x or 8.4.x. Please take the time to update to a supported version after installing this security update.",
					"If you are running 8.3.x, upgrade to Drupal 8.3.9.",
					"If you are running 8.4.x, upgrade to Drupal 8.4.6.",
					"This issue also affects Drupal 8.2.x and earlier, which are no longer supported. If you are running any of these versions of Drupal 8, update to a more recent release and then follow the instructions above.",
				},
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
				Recommendations: []string{
					"Install the latest version:",
					"If you are using Drupal 8 , upgrade to Drupal 8.4.5",
					"If you are using Drupal 7 , upgrade to Drupal 7.57",
				},
			},
		},
	}
)
