package main

import (
	report "github.com/adevinta/vulcan-report"
)

var pluginVulnScores = map[string]float32{
	"WordPress plugin AddToAny Share Buttons <= 1.7.14 - Conditional Host Header Injection":                              report.SeverityThresholdMedium,
	"WordPress plugin Contextual Related Posts 1.8.10.1 - contextual-related-posts.php Multiple Parameter SQL Injection": report.SeverityThresholdHigh,
	"WordPress plugin Contextual Related Posts 1.8.6 - Cross-Site Request Forgery":                                       report.SeverityThresholdMedium,
	"WordPress plugin Contact Form 7 <= 3.5.2 - File Upload Remote Code Execution":                                       report.SeverityThresholdHigh,
	"WordPress plugin Contact Form 7 <= 3.7.1 - Security Bypass":                                                         report.SeverityThresholdMedium,
	"WordPress plugin Google Analytics by Monster Insights <= 7.1.0 - Authenticated Stored Cross-Site Scripting (XSS)":   report.SeverityThresholdMedium,
	"WordPress plugin Yoast SEO <= 5.7.1 - Authenticated Cross-Site Scripting (XSS)":                                     report.SeverityThresholdMedium,
	"WordPress plugin Gravity Forms <= 1.9.15.11 -  Authenticated Reflected Cross-Site Scripting (XSS)":                  report.SeverityThresholdMedium,
	"WordPress plugin Gravity Forms <= 1.9.6 - Cross-Site Scripting (XSS)":                                               report.SeverityThresholdMedium,
	"WordPress plugin Gravity Forms <= 2.0.6.5 - Authenticated Blind Cross-Site Scripting (XSS)":                         report.SeverityThresholdMedium,
	"WordPress plugin MailPoet Newsletters 2.6.10 - Unspecified CSRF":                                                    report.SeverityThresholdMedium,
	"WordPress plugin MailPoet Newsletters 2.6.6 - Theme File Upload H&ling Remote Code Execution":                       report.SeverityThresholdHigh,
	"WordPress plugin MailPoet Newsletters <= 2.6.19 - Unauthenticated Reflected Cross-Site Scripting (XSS)":             report.SeverityThresholdMedium,
	"WordPress plugin MailPoet Newsletters <= 2.7.2 - Authenticated Reflected Cross-Site Scripting (XSS)":                report.SeverityThresholdMedium,
	"WordPress plugin MailPoet Newsletters <= 2.7.2 - SQL Injection":                                                     report.SeverityThresholdHigh,
	"WordPress plugin Simple Download Monitor <= 3.5.3 - Authenticated Cross-Site Scripting (XSS)":                       report.SeverityThresholdMedium,
	"WordPress plugin WP-Polls <= 2.70 - Stored Cross-Site Scripting (XSS)":                                              report.SeverityThresholdMedium,
	"WordPress plugin WP-Polls <= 2.73 - Authenticated Reflected Cross-Site Scripting (XSS)":                             report.SeverityThresholdMedium,
	"WordPress plugin Wysija Newsletters - swfupload Cross-Site Scripting":                                               report.SeverityThresholdMedium,
	"WordPress plugin Wysija Newsletters 2.2 - SQL Injection":                                                            report.SeverityThresholdMedium,
	"WordPress plugin Yet Another Related Posts Plugin (YARPP) 4.2.4 - CSRF / XSS / RCE":                                 report.SeverityThresholdMedium,
	"WordPress plugin YouTube Embed <= 11.8.1 - Cross-Site Request Forgery (CSRF)":                                       report.SeverityThresholdMedium,
	"WordPress plugin Contact Form 7 <= 5.0.3 - register_post_type() Privilege Escalation":                               report.SeverityThresholdMedium,
	"WordPress plugin Yoast SEO <= 9.1 - Authenticated Race Condition":                                                   report.SeverityThresholdMedium,
	"WordPress plugin MailPoet Newsletters  2.6.7 - helpers/back.php page Parameter Unspecified Issue":                   report.SeverityThresholdNone,
	"WordPress plugin Simple Download Monitor <= 3.2.8 - Insufficient Authorisation":                                     report.SeverityThresholdMedium,
}
