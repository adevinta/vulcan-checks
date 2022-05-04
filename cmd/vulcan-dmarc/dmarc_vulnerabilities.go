/*
Copyright 2019 Adevinta
*/

package main

import (
	"github.com/adevinta/vulcan-check-sdk/helpers"
	report "github.com/adevinta/vulcan-report"
)

var vulns = map[string]report.Vulnerability{
	"dmarc-not-found": report.Vulnerability{
		CWEID:   358,
		Summary: "DMARC DNS Record Not Found",
		Description: "No DMARC policy has been found for this domain.\nA DMARC " +
			"(Domain-based Message Authentication, Reporting and Conformance) policy allows you " +
			"to indicate that email messages from this domain are protected by SPF and DKIM, " +
			"and tells recipients what to do if neither of those authentication methods passes, " +
			"such as junk or reject the message. DMARC limits or eliminates your user's exposure to " +
			"potentially fraudulent and harmful messages, such as phishing. DMARC also provides a way " +
			"for recipients to automatically report back to you about messages that fail DMARC " +
			"evaluation, so that you will be able to know if your email address is being used in " +
			"phishing attacks or if some of your legitimate emails are being marked as spam.",
		Score: report.SeverityThresholdLow,
		ImpactDetails: "An attacker may be able to send email messages that appear to originate " +
			"from this domain without your knowledge, which can be used to perform very convincing " +
			"phishing attacks against your users.",
		Recommendations: []string{
			"Create a DMARC DNS TXT record beginning with 'v=DMARC1'",
			"For easy DMARC deployment in AWS Route53, check our CloudFormation template in References",
		},
		References: []string{
			"https://dmarc.org/",
			"https://en.wikipedia.org/wiki/DMARC",
			"https://tools.ietf.org/html/rfc7489#section-6.3",
		},
		Labels:      []string{"issue", "dns"},
		Fingerprint: helpers.ComputeFingerprint(),
	},
	"multiple-dmarc-found": report.Vulnerability{
		CWEID:   358,
		Summary: "DMARC Multiple Records Found",
		Description: "Multiple DMARC policy records have been found for this domain.\nIf a domain" +
			"contains multiple DMARC records, DMARC will not be processed at all.",
		Score: report.SeverityThresholdLow,
		ImpactDetails: "An attacker may be able to send email messages that appear to originate " +
			"from this domain without your knowledge, which can be used to perform very convincing " +
			"phishing attacks against your users.",
		Recommendations: []string{
			"Create a single DMARC record",
		},
		References: []string{
			"https://dmarc.org/",
			"https://en.wikipedia.org/wiki/DMARC",
			"https://tools.ietf.org/html/rfc7489",
		},
		Labels:      []string{"issue", "dns"},
		Fingerprint: helpers.ComputeFingerprint(),
	},
	"unable-to-parse-tags": report.Vulnerability{
		CWEID:   358,
		Summary: "DMARC Unable To Parse Tags",
		Description: "Some tags present in the DMARC policy record for this domain are invalid.\nIf a domain" +
			"contains invalid DMARC tags or tag values, DMARC will not be processed at all.",
		Score: report.SeverityThresholdLow,
		ImpactDetails: "An attacker may be able to send email messages that appear to originate " +
			"from this domain without your knowledge, which can be used to perform very convincing " +
			"phishing attacks against your users.",
		Recommendations: []string{
			"Review the DMARC record and fix/remove any invalid tags/values",
		},
		References: []string{
			"https://dmarc.org/",
			"https://en.wikipedia.org/wiki/DMARC",
			"https://tools.ietf.org/html/rfc7489#section-6.3",
		},
		Labels:      []string{"issue", "dns"},
		Fingerprint: helpers.ComputeFingerprint(),
	},
	"v-and-p-invalid-or-missing": report.Vulnerability{
		CWEID:   358,
		Summary: "DMARC 'v' And 'p' Are Invalid",
		Description: "Tags 'v' and 'p' are missing or are invalid. A DMARC policy record MUST comply with the formal specification " +
			"in that the 'v' and 'p' tags MUST be present and MUST appear in that order.",
		Score: report.SeverityThresholdLow,
		ImpactDetails: "An attacker may be able to send email messages that appear to originate " +
			"from this domain without your knowledge, which can be used to perform very convincing " +
			"phishing attacks against your users.",
		References: []string{
			"https://dmarc.org/",
			"https://en.wikipedia.org/wiki/DMARC",
			"https://tools.ietf.org/html/rfc7489#section-6.3",
		},
		Recommendations: []string{
			"Review the record sintax and ensure: That 'v' and 'p' are present, have valid values and that they appear in that exact order.",
		},
		Labels:      []string{"issue", "dns"},
		Fingerprint: helpers.ComputeFingerprint(),
	},
	"tag-v-wrong-value": report.Vulnerability{
		CWEID:   358,
		Summary: "DMARC Tag 'v' Has Wrong Value",
		Description: "Version (plain-text; REQUIRED). Identifies the record retrieved " +
			"as a DMARC record.  It MUST have the value of 'DMARC1'.  The value " +
			"of this tag MUST match precisely; if it does not or it is absent, " +
			"the entire retrieved record MUST be ignored.  It MUST be the first" +
			"tag in the list.",
		Score: report.SeverityThresholdLow,
		ImpactDetails: "An attacker may be able to send email messages that appear to originate " +
			"from this domain without your knowledge, which can be used to perform very convincing " +
			"phishing attacks against your users.",
		References: []string{
			"https://dmarc.org/",
			"https://en.wikipedia.org/wiki/DMARC",
			"https://tools.ietf.org/html/rfc7489#section-6.3",
		},
		Recommendations: []string{
			"Review the record syntax and ensure that tag 'v' is set to 'DMARC1'",
		},
		Labels:      []string{"issue", "dns"},
		Fingerprint: helpers.ComputeFingerprint(),
	},
	"tag-p-wrong-value": report.Vulnerability{
		CWEID:   358,
		Summary: "DMARC Tag 'p' Has Wrong Value",
		Description: "The value of tag 'p' is not a valid one. Requested Mail Receiver policy (plain-text; REQUIRED for policy " +
			"records).  Indicates the policy to be enacted by the Receiver at " +
			"the request of the Domain Owner.  Policy applies to the domain " +
			"queried and to subdomains, unless subdomain policy is explicitly " +
			"described using the 'sp' tag.  This tag is mandatory for policy " +
			"records only, but not for third-party reporting records. Possible values are as follows: " +
			"none:  The Domain Owner requests no specific action be taken regarding delivery of messages. " +
			"quarantine:  The Domain Owner wishes to have email that fails the " +
			"DMARC mechanism check be treated by Mail Receivers as " +
			"suspicious.  Depending on the capabilities of the Mail " +
			"Receiver, this can mean 'place into spam folder', 'scrutinize " +
			"with additional intensity', and/or 'flag as suspicious'. " +
			"reject:  The Domain Owner wishes for Mail Receivers to reject " +
			"email that fails the DMARC mechanism check.",
		Score: report.SeverityThresholdLow,
		ImpactDetails: "An attacker may be able to send email messages that appear to originate " +
			"from this domain without your knowledge, which can be used to perform very convincing " +
			"phishing attacks against your users.",
		References: []string{
			"https://dmarc.org/",
			"https://en.wikipedia.org/wiki/DMARC",
			"https://tools.ietf.org/html/rfc7489#section-6.3",
		},
		Recommendations: []string{
			"Review the record syntax and ensure that tag 'p' is set to one of the following values : 'none', 'quarantine' or 'reject'",
		},
		Labels:      []string{"issue", "dns"},
		Fingerprint: helpers.ComputeFingerprint(),
	},
	"tag-p-is-none": report.Vulnerability{
		CWEID:   358,
		Summary: "DMARC Tag 'p' Set To 'none'",
		Description: "The value of tag 'p' is configured as 'none'. It should be set to 'reject'. " +
			"none: The Domain Owner requests no specific action be taken regarding delivery of messages. " +
			"reject:  The Domain Owner wishes for Mail Receivers to reject " +
			"email that fails the DMARC mechanism check.",
		Score: report.SeverityThresholdLow,
		ImpactDetails: "An attacker may be able to send email messages that appear to originate " +
			"from this domain without your knowledge, which can be used to perform very convincing " +
			"phishing attacks against your users.",
		References: []string{
			"https://dmarc.org/",
			"https://en.wikipedia.org/wiki/DMARC",
			"https://tools.ietf.org/html/rfc7489",
		},
		Recommendations: []string{
			"Set tag 'p' to be 'reject'",
		},
		Labels:      []string{"issue", "dns"},
		Fingerprint: helpers.ComputeFingerprint(),
	},
	"tag-p-is-quarantine": report.Vulnerability{
		CWEID:   358,
		Summary: "DMARC Tag 'p' Set To 'quarantine'",
		Description: "The value of tag 'p' is configured as 'quarantine'. It should be set to 'reject'. " +
			"none:  The Domain Owner requests no specific action be taken regarding delivery of messages. " +
			"quarantine:  The Domain Owner wishes to have email that fails the " +
			"DMARC mechanism check be treated by Mail Receivers as " +
			"suspicious.  Depending on the capabilities of the Mail " +
			"Receiver, this can mean 'place into spam folder', 'scrutinize " +
			"with additional intensity', and/or 'flag as suspicious'. ",
		Score: report.SeverityThresholdLow,
		ImpactDetails: "An attacker may be able to send email messages that appear to originate " +
			"from this domain without your knowledge, which can be used to perform very convincing " +
			"phishing attacks against your users.",
		References: []string{
			"https://dmarc.org/",
			"https://en.wikipedia.org/wiki/DMARC",
			"https://tools.ietf.org/html/rfc7489",
		},
		Recommendations: []string{
			"Set tag 'p' to be 'reject'",
		},
		Labels:      []string{"issue", "dns"},
		Fingerprint: helpers.ComputeFingerprint(),
	},
	"tag-rua-not-configured": report.Vulnerability{
		CWEID:   358,
		Summary: "DMARC Tag 'rua' Missing",
		Description: "The tag 'rua' is not explicitly configured. " +
			"rua:  Addresses to which aggregate feedback is to be sent (comma-" +
			"separated plain-text list of DMARC URIs; OPTIONAL).",
		Score: report.SeverityThresholdNone,
		References: []string{
			"https://dmarc.org/",
			"https://en.wikipedia.org/wiki/DMARC",
			"https://tools.ietf.org/html/rfc7489",
		},
		Recommendations: []string{
			"Explicitly define the value of tag 'rua'",
		},
		Labels:      []string{"issue", "dns"},
		Fingerprint: helpers.ComputeFingerprint(),
	},
	"tag-ruf-not-configured": report.Vulnerability{
		CWEID:   358,
		Summary: "DMARC Tag 'ruf' Missing",
		Description: "The tag 'ruf' is not explicitly configured. " +
			"ruf: Addresses to which message-specific failure information is to " +
			"be reported (comma-separated plain-text list of DMARC URIs; " +
			"OPTIONAL). If present, the Domain Owner is requesting Mail " +
			"Receivers to send detailed failure reports about messages that " +
			"fail the DMARC evaluation in specific ways (see the 'fo' tag " +
			"above). The format of the message to be generated MUST follow the " +
			"format specified for the 'rf' tag. ",
		Score: report.SeverityThresholdNone,
		References: []string{
			"https://dmarc.org/",
			"https://en.wikipedia.org/wiki/DMARC",
			"https://tools.ietf.org/html/rfc7489",
		},
		Recommendations: []string{
			"Explicitly define the value of tag 'ruf'",
		},
		Labels:      []string{"issue", "dns"},
		Fingerprint: helpers.ComputeFingerprint(),
	},
	"tag-pct-not-100": report.Vulnerability{
		CWEID:   358,
		Summary: "DMARC Tag 'pct' Is Not Set To '100'",
		Description: "Selective DMARC policy 'pct' is not set to '100'. " +
			"pct:  (plain-text integer between 0 and 100, inclusive; OPTIONAL; " +
			"default is 100).  Percentage of messages from the Domain Owner's " +
			"mail stream to which the DMARC policy is to be applied. ",
		Score: report.SeverityThresholdNone,
		References: []string{
			"https://dmarc.org/",
			"https://en.wikipedia.org/wiki/DMARC",
			"https://tools.ietf.org/html/rfc7489",
		},
		Recommendations: []string{
			"Set tag 'pct' to be '100'",
		},
		Labels:      []string{"issue", "dns"},
		Fingerprint: helpers.ComputeFingerprint(),
	},
	"tag-rua-not-valid-mailto": report.Vulnerability{
		CWEID:   358,
		Summary: "DMARC Tag 'rua' Is Invalid",
		Description: "The 'rua' tag has an invalid value. It should be a comma-separated plain-text list of DMARC URIs. " +
			"rua:  Addresses to which aggregate feedback is to be sent (comma-" +
			"separated plain-text list of DMARC URIs; OPTIONAL).",
		Score: report.SeverityThresholdLow,
		ImpactDetails: "An attacker may be able to send email messages that appear to originate " +
			"from this domain without your knowledge, which can be used to perform very convincing " +
			"phishing attacks against your users.",
		References: []string{
			"https://dmarc.org/",
			"https://en.wikipedia.org/wiki/DMARC",
			"https://tools.ietf.org/html/rfc7489",
		},
		Recommendations: []string{
			"Review the record syntax and ensure that tag 'rua' is a valid list of mail addresses",
		},
		Labels:      []string{"issue", "dns"},
		Fingerprint: helpers.ComputeFingerprint(),
	},
	"tag-ruf-not-valid-mailto": report.Vulnerability{
		CWEID:   358,
		Summary: "DMARC Tag 'ruf' Is Invalid",
		Description: "The 'ruf' tag has an invalid value. It should be a comma-separated plain-text list of DMARC URIs." +
			"ruf: Addresses to which message-specific failure information is to " +
			"be reported (comma-separated plain-text list of DMARC URIs; " +
			"OPTIONAL).",
		Score: report.SeverityThresholdLow,
		ImpactDetails: "An attacker may be able to send email messages that appear to originate " +
			"from this domain without your knowledge, which can be used to perform very convincing " +
			"phishing attacks against your users.",
		References: []string{
			"https://dmarc.org/",
			"https://en.wikipedia.org/wiki/DMARC",
			"https://tools.ietf.org/html/rfc7489",
		},
		Recommendations: []string{
			"Review the record syntax and ensure that tag 'ruf' is a valid list of mail addresses",
		},
		Labels:      []string{"issue", "dns"},
		Fingerprint: helpers.ComputeFingerprint(),
	},
	"tag-adkim-not-valid": report.Vulnerability{
		CWEID:   358,
		Summary: "DMARC Tag 'adkim' Is Invalid",
		Description: "The 'adkim' tag has an invalid value. " +
			"adkim: (plain-text; OPTIONAL; default is 'r'.) Indicates whether " +
			"strict or relaxed DKIM Identifier Alignment mode is required by " +
			"the Domain Owner. Valid values are as follows: [r: relaxed mode, s: strict mode]",
		Score: report.SeverityThresholdLow,
		ImpactDetails: "An attacker may be able to send email messages that appear to originate " +
			"from this domain without your knowledge, which can be used to perform very convincing " +
			"phishing attacks against your users.",
		References: []string{
			"https://dmarc.org/",
			"https://en.wikipedia.org/wiki/DMARC",
			"https://tools.ietf.org/html/rfc7489",
		},
		Recommendations: []string{
			"Review the record syntax and ensure that tag 'adkim' is set to one of the following values : 'r' or 's'",
		},
		Labels:      []string{"issue", "dns"},
		Fingerprint: helpers.ComputeFingerprint(),
	},
	"tag-aspf-not-valid": report.Vulnerability{
		CWEID:   358,
		Summary: "DMARC Tag 'aspf' Is Invalid",
		Description: "The 'aspf' tag has an invalid value. " +
			"aspf:  (plain-text; OPTIONAL; default is 'r'.)  Indicates whether " +
			"strict or relaxed SPF Identifier Alignment mode is required by the " +
			"Domain Owner. Valid values are as follows: [r: relaxed mode, s: strict mode] ",
		Score: report.SeverityThresholdLow,
		ImpactDetails: "An attacker may be able to send email messages that appear to originate " +
			"from this domain without your knowledge, which can be used to perform very convincing " +
			"phishing attacks against your users.",
		References: []string{
			"https://dmarc.org/",
			"https://en.wikipedia.org/wiki/DMARC",
			"https://tools.ietf.org/html/rfc7489",
		},
		Recommendations: []string{
			"Review the record syntax and ensure that tag 'aspf' is set to one of the following values : 'r' or 's'",
		},
		Labels:      []string{"issue", "dns"},
		Fingerprint: helpers.ComputeFingerprint(),
	},
	"tag-sp-not-valid": report.Vulnerability{
		CWEID:   358,
		Summary: "DMARC Tag 'sp' Is Invalid",
		Description: "The 'sp' tag has an invalid value. " +
			"sp:  Requested Mail Receiver policy for all subdomains (plain-text; " +
			"OPTIONAL).  Indicates the policy to be enacted by the Receiver at " +
			"the request of the Domain Owner.  It applies only to subdomains of " +
			"the domain queried and not to the domain itself.  Possible values are as follows: " +
			"none:  The Domain Owner requests no specific action be taken regarding delivery of messages. " +
			"quarantine:  The Domain Owner wishes to have email that fails the " +
			"DMARC mechanism check be treated by Mail Receivers as " +
			"suspicious.  Depending on the capabilities of the Mail " +
			"Receiver, this can mean 'place into spam folder', 'scrutinize " +
			"with additional intensity', and/or 'flag as suspicious'. " +
			"reject:  The Domain Owner wishes for Mail Receivers to reject " +
			"email that fails the DMARC mechanism check.",
		Score: report.SeverityThresholdLow,
		ImpactDetails: "An attacker may be able to send email messages that appear to originate " +
			"from this domain without your knowledge, which can be used to perform very convincing " +
			"phishing attacks against your users.",
		References: []string{
			"https://dmarc.org/",
			"https://en.wikipedia.org/wiki/DMARC",
			"https://tools.ietf.org/html/rfc7489",
		},
		Recommendations: []string{
			"Review the record syntax and ensure that tag 'sp' is set to one of the following values: 'none', 'quarantine' or 'reject'",
		},
		Labels:      []string{"issue", "dns"},
		Fingerprint: helpers.ComputeFingerprint(),
	},
	"tag-fo-not-valid": report.Vulnerability{
		CWEID:   358,
		Summary: "DMARC Tag 'fo' Is Invalid",
		Description: "The 'fo' tag has an invalid value. " +
			"fo:  Failure reporting options (plain-text; OPTIONAL; default is '0')" +
			"Provides requested options for generation of failure reports. " +
			"Report generators MAY choose to adhere to the requested options. " +
			"This tag's content MUST be ignored if a 'ruf' tag is not " +
			"also specified.  The value of this tag is a colon-separated list " +
			"of characters that indicate failure reporting options as follows: " +
			"0: Generate a DMARC failure report if all underlying authentication mechanisms fail to produce an aligned 'pass' result. " +
			"1: Generate a DMARC failure report if any underlying authentication mechanism produced something other than an aligned 'pass' result. " +
			"d: Generate a DKIM failure report if the message had a signature that failed evaluation, regardless of its alignment. " +
			"s: Generate an SPF failure report if the message failed SPF evaluation, regardless of its alignment. ",
		Score: report.SeverityThresholdLow,
		ImpactDetails: "An attacker may be able to send email messages that appear to originate " +
			"from this domain without your knowledge, which can be used to perform very convincing " +
			"phishing attacks against your users.",
		References: []string{
			"https://dmarc.org/",
			"https://en.wikipedia.org/wiki/DMARC",
			"https://tools.ietf.org/html/rfc7489",
		},
		Recommendations: []string{
			"Review the record syntax and ensure that tag 'fo' is set to one of the following values: '0', '1', 'd' or 's'",
		},
		Labels:      []string{"issue", "dns"},
		Fingerprint: helpers.ComputeFingerprint(),
	},
	"tag-rf-not-valid": report.Vulnerability{
		CWEID:   358,
		Summary: "DMARC Tag 'rf' Is Invalid",
		Description: "The 'rf' tag has an invalid value. " +
			"rf:  Format to be used for message-specific failure reports (colon- " +
			"separated plain-text list of values; OPTIONAL; default is 'afrf'). " +
			"The value of this tag is a list of one or more report formats as " +
			"requested by the Domain Owner to be used when a message fails both " +
			"[SPF] and [DKIM] tests to report details of the individual " +
			"failure.  For this version, only 'afrf' (the auth-failure report " +
			"type) is presently supported. ",
		Score: report.SeverityThresholdLow,
		ImpactDetails: "An attacker may be able to send email messages that appear to originate " +
			"from this domain without your knowledge, which can be used to perform very convincing " +
			"phishing attacks against your users.",
		References: []string{
			"https://dmarc.org/",
			"https://en.wikipedia.org/wiki/DMARC",
			"https://tools.ietf.org/html/rfc7489",
		},
		Recommendations: []string{
			"Review the record syntax and ensure that tag 'rf' is set to 'afrf'",
		},
		Labels:      []string{"issue", "dns"},
		Fingerprint: helpers.ComputeFingerprint(),
	},
	"tag-ri-not-valid": report.Vulnerability{
		CWEID:   358,
		Summary: "DMARC Tag 'ri' Is Invalid",
		Description: "The 'ri' tag has an invalid value. " +
			"ri:  Interval requested between aggregate reports (plain-text 32-bit " +
			"unsigned integer; OPTIONAL; default is 86400).  Indicates a " +
			"request to Receivers to generate aggregate reports separated by no " +
			"more than the requested number of seconds. ",
		Score: report.SeverityThresholdLow,
		ImpactDetails: "An attacker may be able to send email messages that appear to originate " +
			"from this domain without your knowledge, which can be used to perform very convincing " +
			"phishing attacks against your users.",
		References: []string{
			"https://dmarc.org/",
			"https://en.wikipedia.org/wiki/DMARC",
			"https://tools.ietf.org/html/rfc7489",
		},
		Recommendations: []string{
			"Review the record syntax and ensure that tag 'ri' is set to an integer",
		},
		Labels:      []string{"issue", "dns"},
		Fingerprint: helpers.ComputeFingerprint(),
	},
}
