package main

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/adevinta/vulcan-check-sdk/state"
	"github.com/adevinta/vulcan-report"
)

// CSP group of vulnerabilities.
var cspVuln = report.Vulnerability{
	Description: "Content Security Policy (CSP) is an HTTP header that allows site operators fine-grained control over where resources on their site can be loaded from. " +
		"The use of this header is the best method to prevent cross-site scripting (XSS) vulnerabilities. " +
		"Due to the difficulty in retrofitting CSP into existing websites, CSP is mandatory for all new websites and is strongly recommended for all existing high-risk sites.",
	Score: 1.0, // Low.
	CWEID: 358,
	Recommendations: []string{
		"Implement a well-formed and correct CSP policy for this site.",
		"The policy should not contain unsafe directive for anything but style.",
		"The policy should not allow to load content from an insecure scheme (only https).",
	},
	References: []string{
		"https://wiki.mozilla.org/Security/Guidelines/Web_Security#Content_Security_Policy",
		"https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
		"https://content-security-policy.com/",
		"https://observatory.mozilla.org/",
	},
}

// processCSP checks the Observatory scan results and adds a Vulnerability if a misconfiguration is found.
func processCSP(r observatoryResult, s state.State) error {
	add := false

	switch r.Tests.ContentSecurityPolicy.Result {
	case `csp-not-implemented`:
		cspVuln.Summary = "HTTP Content Security Policy Not Implemented"
		cspVuln.Score = report.SeverityThresholdLow // 3.9
		add = true
	case `csp-header-invalid`:
		cspVuln.Summary = "HTTP Content Security Policy Is Malformed"
		cspVuln.Score = report.SeverityThresholdLow // 3.9
		add = true
	default:
		cspVuln.Summary = "HTTP Content Security Policy Implemented Unsafely"
		var err error
		add, err = processCSPPolicy(r, s)
		if err != nil {
			return err
		}
	}

	if add {
		s.AddVulnerabilities(cspVuln)
	}

	return nil
}

// cspDetails contains details for cases when the observatory grade is negative.
// https://github.com/mozilla/http-observatory/blob/master/httpobs/scanner/grader/grade.py#L79
var cspDetails = map[string]string{
	"csp-implemented-with-insecure-scheme-in-passive-content-only": "* CSP allows images or media to be loaded over HTTP.",
	"csp-implemented-with-unsafe-eval":                             "* CSP allows 'unsafe-eval'.",
	"csp-implemented-with-unsafe-inline": "* CSP includes 'unsafe-inline' or 'data:' inside 'script-src', overly broad sources " +
		"such as 'https:' inside 'object-src' or 'script-src', or not restricting the sources for 'object-src' or 'script-src'.",
	"csp-implemented-with-insecure-scheme": "* CSP allows resources to be loaded from HTTP.",
}

// processPolicy will parse the Policy struct obtained from the Observatory scan.
// The policy is a map where keys are the name of a (mis)configuration and the value
// is a bool that indicates whether it applies or not.
func processCSPPolicy(r observatoryResult, s state.State) (add bool, err error) {
	// As the CSP header exists and is well-formed, the field Policy should exist in the Test results.
	var p interface{}
	if err := json.Unmarshal(r.Tests.ContentSecurityPolicy.Policy, &p); err != nil {
		return false, err
	}

	m, ok := p.(map[string]interface{})
	if !ok {
		return false, errors.New("CSP test policy unexpected format")
	}

	for k, v := range m {
		policyValue, ok := v.(bool)
		if !ok {
			return false, errors.New("CSP test policy unexpected format")
		}

		// Add vulnerability if the value in the policy is true and has a negative modifier.
		if policyValue && cspDetails[k] != "" {
			add = true

			// Include newline if there are more than one details bullet.
			if cspVuln.Details != "" {
				cspVuln.Details += "\n"
			}

			cspVuln.Details += cspDetails[k]
		}
	}

	return add, nil
}

// Cookies group of vulnerabilities.
var cookiesVuln = report.Vulnerability{
	Summary: "HTTP Cookies Misconfiguration",
	Description: "All cookies should be created such that their access is as limited as possible. " +
		"This can help minimize damage from cross-site scripting (XSS) vulnerabilities, " +
		"as these cookies often contain session identifiers or other sensitive information.",
	CWEID: 358,
	Recommendations: []string{
		"All cookies should use the Secure flag.",
		"Session cookies should use the HttpOnly flag.",
		"Cross-origin restrictions should be in place via the SameSite flag.",
	},
	References: []string{
		"https://wiki.mozilla.org/Security/Guidelines/Web_Security#Cookies",
		"https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies",
		"https://observatory.mozilla.org/",
	},
}

// processCookies checks the Observatory scan results and adds a Vulnerability if a misconfiguration is found.
func processCookies(r observatoryResult, s state.State) {
	add := true

	switch r.Tests.Cookies.Result {
	case `cookies-without-secure-flag-but-protected-by-hsts`:
		cookiesVuln.Details = "Cookies set without using the 'Secure' flag, but transmission over HTTP prevented by HSTS."
		cookiesVuln.Score = report.SeverityThresholdNone
	case `cookies-session-without-secure-flag-but-protected-by-hsts`:
		cookiesVuln.Details = "Session cookie set without the 'Secure' flag, but transmission over HTTP prevented by HSTS."
		cookiesVuln.Score = report.SeverityThresholdNone
	case `cookies-without-secure-flag`:
		cookiesVuln.Details = "Cookies set without using the 'Secure' flag or set over HTTP."
		cookiesVuln.Score = 2.0 // Low.
	case `cookies-samesite-flag-invalid`:
		cookiesVuln.Details = "Cookies use 'SameSite' flag, but set to something other than 'Strict' or 'Lax'."
		cookiesVuln.Score = 2.0 // Low.
	case `cookies-anticsrf-without-samesite-flag`:
		cookiesVuln.Details = "Anti-CSRF tokens set without using the 'SameSite' flag."
		cookiesVuln.Score = 2.0 // Low.
	case `cookies-session-without-httponly-flag`:
		cookiesVuln.Details = "Session cookie set without using the 'HttpOnly' flag."
		cookiesVuln.Score = 3.0 // Low.
	case `cookies-session-without-secure-flag`:
		cookiesVuln.Details = "Session cookie set without using the 'Secure' flag or set over HTTP."
		cookiesVuln.Score = report.SeverityThresholdLow // 3.9
	default:
		add = false
	}

	if add {
		s.AddVulnerabilities(cookiesVuln)
	}
}

// CORS vulnerability.
var corsVuln = report.Vulnerability{
	Summary: "Cross-Origin Resource Sharing Implemented with Universal Access",
	Description: "`Access-Control-Allow-Origin` is an HTTP header that defines which foreign origins are allowed to access the content " +
		"of pages on your domain via scripts using methods such as XMLHttpRequest. The `crossdomain.xml` and `clientaccesspolicy.xml` provide " +
		"similar functionality, but for Flash and Silverlight-based applications, respectively.",
	Score: report.SeverityThresholdMedium,
	ImpactDetails: "Incorrectly configured CORS settings can allow foreign sites to read your site's contents, possibly allowing them access " +
		"to private user information.",
	CWEID: 358,
	Recommendations: []string{
		"CORS should not be present unless specifically needed.",
		"If present, it should be locked down to as few origins and resources as is needed for proper function.",
	},
	References: []string{
		"https://wiki.mozilla.org/Security/Guidelines/Web_Security#Cross-origin_Resource_Sharing",
		"https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS",
		"https://observatory.mozilla.org/",
	},
}

// processCORS checks the Observatory scan results and adds a Vulnerability if a misconfiguration is found.
func processCORS(r observatoryResult, s state.State) {
	add := false

	if r.Tests.CrossOriginResourceSharing.Result == `xml-not-parsable` {
		corsVuln.Details += "* Claims to be xml, but cannot be parsed."
		corsVuln.Recommendations = append(corsVuln.Recommendations, "Fix /crossdomain.xml and/or /clientaccesspolicy.xml so it becomes well-formed to be able to run the CORS check.")
		corsVuln.Score = report.SeverityThresholdLow // 3.9
		add = true
	}

	if r.Tests.CrossOriginResourceSharing.Result == `cross-origin-resource-sharing-implemented-with-universal-access` {
		if corsVuln.Details != "" {
			corsVuln.Details += "\n"
		}
		corsVuln.Details += "* Content is visible via cross-origin resource sharing (CORS) file or headers."
		add = true
	}

	if add {
		s.AddVulnerabilities(corsVuln)
	}
}

// Redirection vulnerabilities.
var redirectVulns = report.Vulnerability{
	Summary: "HTTP Redirect Misconfiguration",
	Description: "Websites may continue to listen on port 80 (HTTP) so that users do not get connection errors when typing a URL into their address bar, " +
		"as browsers currently connect via HTTP for their initial request. Sites that listen on port 80 should only redirect to the same resource on HTTPS. " +
		"Once the redirection has occured, HSTS should ensure that all future attempts go to the site via HTTP are instead sent directly to the secure site. " +
		"APIs or websites not intended for public consumption should disable the use of HTTP entirely.",
	CWEID: 358,
	Recommendations: []string{
		"Redirect HTTP version of the site to HTTPS.",
		"HTTP to HTTPS redirections should be done with the 301 redirects, unless they redirect to a different path, in which case they may be done with 302 redirections.",
		"Sites should avoid redirections from HTTP to HTTPS on a different host, as this prevents HSTS from being set.",
	},
	References: []string{
		"https://wiki.mozilla.org/Security/Guidelines/Web_Security#HTTP_Redirections",
		"https://developer.mozilla.org/en-US/docs/Web/HTTP/Redirections",
		"https://observatory.mozilla.org/",
	},
}

// processRedirect checks the Observatory scan results and adds a Vulnerability if a misconfiguration is found.
func processRedirect(r observatoryResult, s state.State) {
	add := true

	switch r.Tests.Redirection.Result {
	case `redirection-off-host-from-http`:
		redirectVulns.Details = "* Initial redirection from HTTP to HTTPS is to a different host, preventing HSTS."
		redirectVulns.Score = 1.0 // Low.
	case `redirection-not-to-https-on-initial-redirection`:
		redirectVulns.Details = "* Redirects to HTTPS eventually, but initial redirection is to another HTTP URL."
		redirectVulns.Score = 1.5 // Low.
	case `redirection-not-to-https`:
		redirectVulns.Details = "* Redirects, but final destination is not an HTTPS URL. Final Destination: " + r.Tests.Redirection.Destination
		redirectVulns.Score = report.SeverityThresholdMedium
	case `redirection-missing`:
		redirectVulns.Summary = "Site Without HTTPS"
		redirectVulns.Details = "* Does not redirect to an HTTPS site."
		redirectVulns.Score = report.SeverityThresholdMedium
		redirectVulns.References = append(redirectVulns.References, "https://security.googleblog.com/2018/02/a-secure-web-is-here-to-stay.html")
		redirectVulns.Recommendations = append(redirectVulns.Recommendations, "Serve the site via HTTPS instead of HTTP.")
	case `redirection-invalid-cert`:
		redirectVulns.Details = "* Invalid certificate chain encountered during redirection."
		redirectVulns.Score = 2.0 // Low.
	default:
		add = false
	}

	if add {
		s.AddVulnerabilities(redirectVulns)
	}
}

// Referrer vulnerabilities.
var referrerVulns = report.Vulnerability{
	Summary: "HTTP Referrer Policy Misconfiguration",
	Description: "When a user navigates to a site via a hyperlink or a website loads an external resource, " +
		"browsers inform the destination site of the origin of the requests through the use of the HTTP Referer (sic) header. " +
		"Although this can be useful for a variety of purposes, it can also place the privacy of users at risk. " +
		"HTTP Referrer Policy allows sites to have fine-grained control over how and when browsers transmit the HTTP Referer header.",
	Score: 1.0, // Low.
	CWEID: 358,
	References: []string{
		"https://wiki.mozilla.org/Security/Guidelines/Web_Security#Referrer_Policy",
		"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy",
		"https://observatory.mozilla.org/",
	},
}

// processReferrer checks the Observatory scan results and adds a Vulnerability if a misconfiguration is found.
func processReferrer(r observatoryResult, s state.State) {
	add := true

	switch r.Tests.ReferrerPolicy.Result {
	case `referrer-policy-unsafe`:
		referrerVulns.Details = "* 'Referrer-Policy' header set unsafely to 'origin', 'origin-when-cross-origin', or 'unsafe-url'."
	case `referrer-policy-header-invalid`:
		referrerVulns.Details = "* 'Referrer-Policy' header cannot be recognized."
		referrerVulns.Recommendations = append(referrerVulns.Recommendations, "Fix the malformed Referrer Policy in the HTTP Header.")
	default:
		add = false
	}

	if add {
		s.AddVulnerabilities(referrerVulns)
	}
}

// HSTS vulnerabilities.
var hstsVulns = report.Vulnerability{
	Summary: "HTTP Strict Transport Security Misconfiguration",
	Description: "HTTP Strict Transport Security (HSTS) is an HTTP header that notifies user agents to only connect to a given site over HTTPS, " +
		"even if the scheme chosen was HTTP. Browsers that have had HSTS set for a given site will transparently upgrade all requests to HTTPS. " +
		"HSTS also tells the browser to treat TLS and certificate-related errors more strictly by disabling the ability for users to bypass the error page.",
	CWEID: 358,
	References: []string{
		"https://wiki.mozilla.org/Security/Guidelines/Web_Security#HTTP_Strict_Transport_Security",
		"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
		"https://observatory.mozilla.org/",
	},
}

// processHSTS checks the Observatory scan results and adds a Vulnerability if a misconfiguration is found.
func processHSTS(r observatoryResult, s state.State) {
	add := true

	switch r.Tests.StrictTransportSecurity.Result {
	case `hsts-implemented-max-age-less-than-six-months`:
		hstsVulns.Details = "* HTTP Strict Transport Security (HSTS) header set to less than six months (15768000)."
		hstsVulns.Recommendations = append(
			hstsVulns.Recommendations,
			"max-age must be set to a minimum of six months (15768000), but longer periods such as two years (63072000) are recommended. "+
				"Note that once this value is set, the site must continue to support HTTPS until the expiry time has been reached.",
		)
	case `hsts-not-implemented`:
		hstsVulns.Summary = "HTTP Strict Transport Security Not Implemented"
		hstsVulns.Recommendations = append(hstsVulns.Recommendations, "Implement HSTS in the site.")
		hstsVulns.Score = 1.5 // Low.
	case `hsts-header-invalid`:
		hstsVulns.Details = "* HTTP Strict Transport Security (HSTS) header cannot be recognized."
		hstsVulns.Recommendations = append(hstsVulns.Recommendations, "Fix the malformed HSTS header.")
		hstsVulns.Score = 2.0 // Low.
	case `hsts-not-implemented-no-https`:
		hstsVulns.Details = "* HTTP Strict Transport Security (HSTS) header cannot be set for sites not available over https."
		hstsVulns.Recommendations = append(hstsVulns.Recommendations, "Consider implementing HTTPS in your site, and enable HSTS.")
		hstsVulns.Score = 2.0 // Low.
	case `hsts-invalid-cert`:
		hstsVulns.Details = "* HTTP Strict Transport Security (HSTS) header cannot be set, as site contains an invalid certificate chain."
		hstsVulns.Recommendations = append(hstsVulns.Recommendations, "Fix the certificate chain of the site.")
		hstsVulns.Score = 2.0 // Low.
	default:
		add = false
	}

	if add {
		s.AddVulnerabilities(hstsVulns)
	}
}

// SRI vulnerabilities.
var sriVulns = report.Vulnerability{
	Summary: "HTTP Subresource Integrity Misconfiguration",
	Description: "Subresource integrity is a recent W3C standard that protects against attackers modifying the contents of JavaScript libraries " +
		"hosted on content delivery networks (CDNs) in order to create vulnerabilities in all websites that make use of that hosted library. " +
		"Subresource integrity locks an external JavaScript resource to its known contents at a specific point in time. " +
		"If the file is modified at any point thereafter, supporting web browsers will refuse to load it. As such, " +
		"the use of subresource integrity is mandatory for all external JavaScript resources loaded from sources not hosted on Mozilla-controlled systems.",
	CWEID: 358,
	Recommendations: []string{
		"Add the 'integrity' attribute to every external resource loaded into the webpage.",
		"Load external resources from https.",
	},
	References: []string{
		"https://wiki.mozilla.org/Security/Guidelines/Web_Security#Subresource_Integrity",
		"https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity",
		"https://observatory.mozilla.org/",
	},
}

// processSRI checks the Observatory scan results and adds a Vulnerability if a misconfiguration is found.
func processSRI(r observatoryResult, s state.State) {
	add := true

	switch r.Tests.SubresourceIntegrity.Result {
	case `sri-not-implemented-but-external-scripts-loaded-securely`:
		sriVulns.Details = "* Subresource Integrity (SRI) not implemented, but all external scripts are loaded over HTTPS."
		sriVulns.Score = 1.0 // Low.
	case `sri-implemented-but-external-scripts-not-loaded-securely`:
		sriVulns.Details = "* Subresource Integrity (SRI) implemented, but external scripts are loaded over HTTP."
		sriVulns.Score = report.SeverityThresholdLow // 3.9
	case `sri-not-implemented-and-external-scripts-not-loaded-securely`:
		sriVulns.Details = "* Subresource Integrity (SRI) is not implemented, and external scripts are loaded over HTTP."
		sriVulns.Score = report.SeverityThresholdMedium // 6.9
	case `html-not-parsable`:
		sriVulns.Details = "* Claims to be HTML, but cannot be parsed."
		sriVulns.Recommendations = append(sriVulns.Recommendations, "Fix HTML so it becomes well-formed to be able to run the SRI check.")
		sriVulns.Score = report.SeverityThresholdLow // 3.9
	default:
		add = false
	}

	if add {
		s.AddVulnerabilities(sriVulns)
	}
}

// X-Content-Type-Options vulnerabilities.
var xContentVulns = report.Vulnerability{
	Summary: "HTTP X-Content-Type-Options Misconfiguration",
	Description: "`X-Content-Type-Options` is a header supported by Internet Explorer, Chrome and Firefox 50+ that tells it " +
		"not to load scripts and stylesheets unless the server indicates the correct MIME type. Without this header, " +
		"these browsers can incorrectly detect files as scripts and stylesheets, leading to XSS attacks.",
	Score: 1.0, // Low.
	CWEID: 358,
	Recommendations: []string{
		"All sites must set the X-Content-Type-Options header and the appropriate MIME types for files that they serve.",
	},
	References: []string{
		"https://wiki.mozilla.org/Security/Guidelines/Web_Security#X-Content-Type-Options",
		"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options",
		"https://observatory.mozilla.org/",
	},
}

// processXContent checks the Observatory scan results and adds a Vulnerability if a misconfiguration is found.
func processXContent(r observatoryResult, s state.State) {
	add := true

	switch r.Tests.XContentTypeOptions.Result {
	case `x-content-type-options-not-implemented`:
		xContentVulns.Summary = "HTTP X-Content-Type-Options Not Implemented"
	case `x-content-type-options-header-invalid`:
		xContentVulns.Details = "* 'X-Content-Type-Options' header cannot be recognized."
		xContentVulns.Recommendations = append(xContentVulns.Recommendations, "Fix the malformed X-Content-Type-Options HTTP Header.")
	default:
		add = false
	}

	if add {
		s.AddVulnerabilities(xContentVulns)
	}
}

// X-Frame-Options vulnerabilities.
var xFrameVulns = report.Vulnerability{
	Summary: "HTTP X-Frame-Options Misconfiguration",
	Description: "`X-Frame-Options` is an HTTP header that allows sites control over how your site may be framed within an iframe. " +
		"Clickjacking is a practical attack that allows malicious sites to trick users into clicking links on your site even though " +
		"they may appear to not be on your site at all. As such, the use of the `X-Frame-Options` header is mandatory for all new websites, " +
		"and all existing websites are expected to add support for `X-Frame-Options` as soon as possible.",
	Score: report.SeverityThresholdLow, // 3.9
	CWEID: 358,
	Recommendations: []string{
		"Sites that require the ability to be iframed must use either Content Security Policy and/or employ JavaScript defenses to prevent clickjacking from malicious origins.",
	},
	References: []string{
		"https://wiki.mozilla.org/Security/Guidelines/Web_Security#X-Frame-Options",
		"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options",
		"https://observatory.mozilla.org/",
	},
}

// processXFrame checks the Observatory scan results and adds a Vulnerability if a misconfiguration is found.
func processXFrame(r observatoryResult, s state.State) {
	add := true

	switch r.Tests.XFrameOptions.Result {
	case `x-frame-options-not-implemented`:
		xFrameVulns.Summary = "HTTP X-Frame-Options Not Implemented"
	case `x-frame-options-header-invalid`:
		xFrameVulns.Details = "* 'X-Frame-Options' (XFO) header cannot be recognized."
		xFrameVulns.Recommendations = append(xFrameVulns.Recommendations, "Fix the malformed X-Frame-Options HTTP Header.")
	default:
		add = false
	}

	if add {
		s.AddVulnerabilities(xFrameVulns)
	}
}

// X-XSS-Protection vulnerabilities.
var xXSSVulns = report.Vulnerability{
	Summary: "HTTP X-XSS-Protection Misconfiguration",
	Description: "`X-XSS-Protection` is a feature of Internet Explorer and Chrome that stops pages from loading when they detect reflected cross-site scripting (XSS) attacks. " +
		"Although these protections are largely unnecessary in modern browsers when sites implement a strong Content Security Policy that disables the use of " +
		"inline JavaScript (`unsafe-inline`), they can still provide protections for users of older web browsers that don't yet support CSP.",
	Score: 2.0, // Low.
	CWEID: 358,
	Recommendations: []string{
		"New websites should use this header, but given the small risk of false positives, it is only recommended for existing sites.",
		"This header is unnecessary for APIs, which should instead simply return a restrictive Content Security Policy header.",
	},
	References: []string{
		"https://wiki.mozilla.org/Security/Guidelines/Web_Security#X-XSS-Protection",
		"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection",
		"https://observatory.mozilla.org/",
	},
}

// processXXSS checks the Observatory scan results and adds a Vulnerability if a misconfiguration is found.
func processXXSS(r observatoryResult, s state.State) {
	add := true

	switch r.Tests.XXSSProtection.Result {
	case `x-xss-protection-disabled`:
		xXSSVulns.Details = "* 'X-XSS-Protection' header set to '0' (disabled)."
	case `x-xss-protection-not-implemented`:
		xXSSVulns.Summary = "HTTP X-XSS-Protection Not Implemented"
	case `x-xss-protection-header-invalid`:
		xXSSVulns.Details = "* 'X-XSS-Protection' header cannot be recognized."
		xXSSVulns.Recommendations = append(xXSSVulns.Recommendations, "Fix the malformed X-XSS-Protection HTTP Header.")
	default:
		add = false
	}

	if add {
		s.AddVulnerabilities(xXSSVulns)
	}
}

// Mozilla Observatory Global Grading Info.
var observatoryGrading = report.Vulnerability{
	Summary: "Mozilla HTTP Observatory",
	Description: "The Mozilla HTTP Observatory is a set of tools to analyze your website and inform you if you are utilizing the many available methods to secure it. " +
		"Some of the HTTP check results shown in this report come from using this tool. As the tool is giving a global score, we are showing it to you too. ",
	Score: report.SeverityThresholdNone,
	Recommendations: []string{
		"Fix all the vulnerabilities reported for the HTTP headers of your website to improve the score.",
	},
	References: []string{
		"https://github.com/mozilla/http-observatory/blob/master/httpobs/docs/scoring.md",
		"https://observatory.mozilla.org/",
	},
}

// processGrading checks the Observatory scan results and adds the given grading.
func processGrading(r observatoryResult, s state.State) {
	observatoryGrading.Details = fmt.Sprintf("Global score given by Mozilla Observatory: %v", r.Scan.Grade)

	observatoryGrading.Details += "\n\nThe HTTP headers returned by your site were:\n\n"

	for k, v := range r.Scan.ResponseHeaders {
		observatoryGrading.Details += fmt.Sprintf("%v: %v\n", k, v)
	}

	s.AddVulnerabilities(observatoryGrading)
}
