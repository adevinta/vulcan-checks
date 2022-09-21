/*
Copyright 2019 Adevinta
*/

package main

import report "github.com/adevinta/vulcan-report"

var (
	expiredCertificate = report.Vulnerability{
		CWEID:         298,
		Summary:       "Expired Certificate",
		Description:   "The certificate used in this site is expired.",
		Score:         report.SeverityThresholdMedium,
		ImpactDetails: "When the expiration of a certificate is not taken into account, no trust has necessarily been conveyed through it. Therefore, the validity of the certificate cannot be verified and all benefit of the certificate is lost.",
		Labels:        []string{"issue", "ssl"},
		Recommendations: []string{
			"Renew the certificate for this site",
			"Ensure that certificate expiration monitoring is in place",
		},
		References: []string{
			"https://www.acunetix.com/vulnerabilities/web/tls-ssl-certificate-invalid-date", // 5.3 CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L
			"https://www.tenable.com/pvs-plugins/7036",                                      // 4.8 CVSS:2.0/AV:N/AC:L/Au:N/C:N/I:P/A:N
			"https://www.rapid7.com/db/vulnerabilities/tls-server-cert-expired",             // 6.8 CVSS:2.0/AV:N/AC:M/Au:N/C:P/I:P/A:P
			"https://www.rapid7.com/db/vulnerabilities/https-server-cert-expired",           // 4.3 CVSS:2.0/AV:N/AC:M/Au:N/C:N/I:P/A:N
		},
	}

	criticalCertificateExpiration = report.Vulnerability{
		CWEID:         298,
		Summary:       "Certificate About To Expire",
		Description:   "The certificate used in this site will expire soon.",
		Score:         report.SeverityThresholdMedium,
		ImpactDetails: "When the expiration of a certificate is not taken into account, no trust has necessarily been conveyed through it. Therefore, the validity of the certificate cannot be verified and all benefit of the certificate is lost.",
		Labels:        []string{"issue", "ssl"},
		Recommendations: []string{
			"Renew the certificate for this site",
			"Ensure that certificate expiration monitoring is in place",
		},
		References: []string{
			"https://www.acunetix.com/vulnerabilities/web/tls-ssl-certificate-about-to-expire", // 5.3 CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N
			"https://www.tenable.com/plugins/nessus/42981",                                     // NONE
			"https://www.rapid7.com/db/vulnerabilities/tls-server-cert-to-expire",              // 1 CVSS:2.0/AV:L/AC:H/Au:N/C:N/I:N/A:N
		},
	}

	warningCertificateExpiration = report.Vulnerability{
		CWEID:         298,
		Summary:       "Certificate About To Expire",
		Description:   "The certificate used in this site will expire soon.",
		Score:         report.SeverityThresholdLow,
		ImpactDetails: "When the expiration of a certificate is not taken into account, no trust has necessarily been conveyed through it. Therefore, the validity of the certificate cannot be verified and all benefit of the certificate is lost.",
		Labels:        []string{"issue", "ssl"},
		Recommendations: []string{
			"Renew the certificate for this site",
			"Ensure that certificate expiration monitoring is in place",
		},
		References: []string{
			"https://www.acunetix.com/vulnerabilities/web/tls-ssl-certificate-about-to-expire", // 5.3 CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N
			"https://www.tenable.com/plugins/nessus/42981",                                     // NONE
			"https://www.rapid7.com/db/vulnerabilities/tls-server-cert-to-expire",              // 1 CVSS:2.0/AV:L/AC:H/Au:N/C:N/I:N/A:N
		},
	}

	certificateHostMismatch = report.Vulnerability{
		CWEID:       297,
		Summary:     "Certificate Host Mismatch",
		Description: "The Common Name (CN) or Subject Alternative Name (SAN) of the certificate used in this site does not match the actual name of the site. This commonly happens when a certificate issued for a site is reused in a different site; usually one that hosts the same content, such as a subdomain or a staging environment.",
		Score:       report.SeverityThresholdMedium,
		ImpactDetails: "Even if a certificate is well-formed, signed, and follows the chain of trust " +
			"it may simply be a valid certificate for a different site than the site that " +
			"the software is interacting with. If the certificate's host-specific data is " +
			"not properly checked - such as the Common Name (CN) in the Subject or the " +
			"Subject Alternative Name (SAN) extension of an X.509 certificate - it may be " +
			"possible for a redirection or spoofing attack to allow a malicious host with " +
			"a valid certificate to provide data, impersonating a trusted host. In order " +
			"to ensure data integrity, the certificate must be valid and it must pertain " +
			"to the site that is being accessed.",
		Labels: []string{"issue", "ssl"},
		Recommendations: []string{
			"Issue a certificate specifically for this site with a matching CN",
			"Add a SAN that matches the name of this site to the certificate",
		},
		References: []string{
			"https://www.rapid7.com/db/vulnerabilities/certificate-common-name-mismatch", // 7.0 CVSS:2.0/AV:N/AC:H/Au:N/C:C/I:C/A:N
			"https://www.tenable.com/plugins/nessus/45411",                               // 5.3 CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N
		},
	}

	certificateAuthorityUntrusted = report.Vulnerability{
		CWEID:         599,
		Summary:       "Untrusted Certificate Authority",
		Description:   "The certificate used in this site is issued by either an invalid or an untrusted Certificate Authority (CA). This could mean that the certificate is self-signed or that is issued by a CA that is not widely trusted.",
		Score:         report.SeverityThresholdMedium,
		ImpactDetails: "This could allow an attacker to use an invalid certificate to claim to be a trusted host, use expired certificates, or conduct other attacks that could be detected if the certificate were properly validated.",
		Labels:        []string{"issue", "ssl"},
		Recommendations: []string{
			"Consider replacing a self-signed certificate for one issued by a trusted CA",
			"Make sure that the CA that issued the certificate for this site is widely trusted",
			"Replace the certificate for this site for one that is issued by a trusted CA",
		},
		References: []string{
			"https://www.rapid7.com/db/vulnerabilities/certificate-common-name-mismatch", // 7.0 CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:N
			"https://www.tenable.com/plugins/nessus/45411",                               // 5.3 CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N
		},
	}
)
