/*
Copyright 2019 Adevinta
*/

package main

import (
	"github.com/adevinta/vulcan-check-sdk/helpers"
	report "github.com/adevinta/vulcan-report"
)

var vulns = map[string]report.Vulnerability{
	// CVSS3    4.3      AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N
	// https://github.com/bugcrowd/vulnerability-rating-taxonomy/blob/a6dcfb43cf26004ab20320071b84f59beda49e22/mappings/cvss_v3.json#L73
	"spf-not-found": report.Vulnerability{
		CWEID:   358,
		Summary: "SPF Policy Not Found",
		//discard records that do not begin with a version section of exactly "v=spf1"
		Description: "No SPF policy has been found for this domain.\nA SPF (Sender Policy Framework) " +
			"policy allows you to detect and block email spoofing by providing a mechanism to allow " +
			"receiving mail exchangers to verify that incoming mail from a domain comes from an IP address " +
			"authorized to send email from this domain. Email spam and phishing often use forged " +
			"'from' addresses and domains, so publishing and checking an SPF policy can be considered " +
			"one of the most reliable and simple to use anti-spam and anti-phishing techniques.",
		Score: 4.3,
		ImpactDetails: "An attacker may be able to send email messages that appear to originate " +
			"from this domain without your knowledge, which can be used to perform very convincing " +
			"phishing attacks against your users.",
		References: []string{
			"http://www.open-spf.org/Introduction/",
			"https://en.wikipedia.org/wiki/Sender_Policy_Framework",
			"https://tools.ietf.org/html/rfc7208#section-4.5",
			"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/quickref-route53.html",
		},
		Recommendations: []string{
			"Create a single SPF TXT record beginning with 'v=spf1'",
			"For easy SPF deployment in AWS Route53, check our CloudFormation template in References",
		},
		Labels:      []string{"issue", "dns"},
		Fingerprint: helpers.ComputeFingerprint(),
	},
	"mechanisms-after-first-all-are-ignored": report.Vulnerability{
		CWEID:   358,
		Summary: "SPF 'all' Is Not The Rightmost Mechanism",
		//Mechanisms after "all" will never be tested.  Mechanisms listed after "all" MUST be ignored.
		Description: "The 'all' mechanism is a test that always matches. It is used as the rightmost " +
			"mechanism in a policy to provide an explicit default. For example: [v=spf1 a mx -all] " +
			"Mechanisms after 'all' will never be tested. Mechanisms listed after 'all' MUST be ignored. ",
		Score: report.SeverityThresholdLow,
		References: []string{
			"http://www.open-spf.org/Introduction/",
			"https://en.wikipedia.org/wiki/Sender_Policy_Framework",
			"https://tools.ietf.org/html/rfc7208#section-5.1",
		},
		Recommendations: []string{
			"Remove any mechanisms and modifiers appearing after 'all'",
		},
		Labels:      []string{"issue", "dns"},
		Fingerprint: helpers.ComputeFingerprint(),
	},
	"no-all-or-redirect": report.Vulnerability{
		CWEID:   358,
		Summary: "SPF Missing 'all' And 'redirect'",
		Description: "It is better to use either a 'redirect' modifier or an 'all' " +
			"mechanism to explicitly terminate processing.  Although there is an " +
			"implicit '?all' at the end of every policy that is not explicitly " +
			"terminated, it aids debugging efforts when it is explicitly provided. " +
			"For example: [v=spf1 +mx -all] or [v=spf1 +mx redirect=_spf.example.com]",
		Score: report.SeverityThresholdNone,
		References: []string{
			"http://www.open-spf.org/Introduction/",
			"https://en.wikipedia.org/wiki/Sender_Policy_Framework",
			"https://tools.ietf.org/html/rfc7208#section-4.7",
		},
		Recommendations: []string{
			"Explictly define an 'all' or a 'redirect'",
		},
		Labels:      []string{"issue", "dns"},
		Fingerprint: helpers.ComputeFingerprint(),
	},
	"all-configured-as-PASS": report.Vulnerability{
		CWEID:   358,
		Summary: "SPF 'all' Configured As 'PASS'",
		Description: "A 'pass' result is an explicit statement that the client is " +
			"authorized to inject mail with the given identity. " +
			"A 'fail' result is an explicit statement that the client is not " +
			"authorized to use the domain in the given identity.",
		Score: 4.3,
		ImpactDetails: "An attacker may be able to send email messages that appear to originate " +
			"from this domain without your knowledge, which can be used to perform very convincing " +
			"phishing attacks against your users.",
		References: []string{
			"http://www.open-spf.org/Introduction/",
			"https://en.wikipedia.org/wiki/Sender_Policy_Framework",
			"https://tools.ietf.org/html/rfc7208#section-2.6.3",
		},
		Recommendations: []string{
			"Set 'all' to '-all' (FAIL)",
		},
		Labels:      []string{"issue", "dns"},
		Fingerprint: helpers.ComputeFingerprint(),
	},
	"all-configured-as-NEUTRAL": report.Vulnerability{
		CWEID:   358,
		Summary: "SPF 'all' Configured As 'NEUTRAL'",
		Description: "A 'neutral' result means the ADMD has explicitly stated that it is " +
			"not asserting whether the IP address is authorized. " +
			"A 'fail' result is an explicit statement that the client is not " +
			"authorized to use the domain in the given identity.",
		Score: report.SeverityThresholdLow,
		References: []string{
			"http://www.open-spf.org/Introduction/",
			"https://en.wikipedia.org/wiki/Sender_Policy_Framework",
			"https://tools.ietf.org/html/rfc7208#section-2.6.2",
		},
		Recommendations: []string{
			"Set 'all' to '-all' (FAIL)",
		},
		Labels:      []string{"issue", "dns"},
		Fingerprint: helpers.ComputeFingerprint(),
	},
	"all-configured-as-SOFTFAIL": report.Vulnerability{
		CWEID:   358,
		Summary: "SPF 'all' Mechanism Configured As 'SOFTFAIL'",
		Description: "A 'softfail' result is a weak statement by the publishing ADMD that " +
			"the host is probably not authorized.  It has not published a " +
			"stronger, more definitive policy that results in a 'fail'. " +
			"A 'fail' result is an explicit statement that the client is not " +
			"authorized to use the domain in the given identity.",
		Score: report.SeverityThresholdLow,
		References: []string{
			"http://www.open-spf.org/Introduction/",
			"https://en.wikipedia.org/wiki/Sender_Policy_Framework",
			"https://tools.ietf.org/html/rfc7208#section-2.6.5",
		},
		Recommendations: []string{
			"Set 'all' to '-all' (FAIL)",
		},
		Labels:      []string{"issue", "dns"},
		Fingerprint: helpers.ComputeFingerprint(),
	},
	"dns-queries-exceeded-limit": report.Vulnerability{
		CWEID:   358,
		Summary: "SPF Queries Exceeded The Maximum Limit",
		// SPF implementations MUST limit the total number of those terms to 10 during SPF evaluation
		Description: "Some mechanisms and modifiers (collectively, 'terms') cause DNS " +
			"queries at the time of evaluation, and some do not.  The following " +
			"terms cause DNS queries: the 'include', 'a', 'mx', 'ptr', and " +
			"'exists' mechanisms, and the 'redirect' modifier.  SPF " +
			"implementations MUST limit the total number of those terms to 10 " +
			"during SPF evaluation, to avoid unreasonable load on the DNS",
		Score: report.SeverityThresholdNone,
		References: []string{
			"http://www.open-spf.org/Introduction/",
			"https://en.wikipedia.org/wiki/Sender_Policy_Framework",
			"https://tools.ietf.org/html/rfc7208#section-4.6.4",
		},
		Recommendations: []string{
			"Review the SPF policy and reduce the number of DNS queries invoked to be equal or less than 10",
		},
		Labels:      []string{"issue", "dns"},
		Fingerprint: helpers.ComputeFingerprint(),
	},
	"multiple-spf-found": report.Vulnerability{
		CWEID:   358,
		Summary: "SPF Multiple Records Found",
		// multiple SPF records are not permitted for the same owner name.
		Description: "A domain name MUST NOT have multiple SPF TXT records that would cause an " +
			"authorization check to select more than one policy.",
		Score: report.SeverityThresholdLow,
		References: []string{
			"http://www.open-spf.org/Introduction/",
			"https://en.wikipedia.org/wiki/Sender_Policy_Framework",
			"https://tools.ietf.org/html/rfc7208#section-3",
		},
		Recommendations: []string{
			"Create a single SPF TXT record",
		},
		Labels:      []string{"issue", "dns"},
		Fingerprint: helpers.ComputeFingerprint(),
	},
}
