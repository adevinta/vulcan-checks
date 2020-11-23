package main

import (
	"context"
	"errors"

	"github.com/FiloSottile/CVE-2016-2107/LuckyMinus20"

	check "github.com/adevinta/vulcan-check-sdk"
	"github.com/adevinta/vulcan-check-sdk/helpers"
	checkstate "github.com/adevinta/vulcan-check-sdk/state"
	report "github.com/adevinta/vulcan-report"
)

const (
	checkName = "vulcan-lucky"
)

var (
	// NOTE: shoulde we decrease to severity LOW?
	// https://www.rapid7.com/db/vulnerabilities/ssl-cbc-ciphers     2.6    CVSS2  AV:N/AC:H/Au:N/C:P/I:N/A:N
	// https://nvd.nist.gov/vuln/detail/CVE-2013-0169                2.6    CVSS2  AV:N/AC:H/Au:N/C:P/I:N/A:N
	luckyVuln = report.Vulnerability{
		CWEID:   310,
		Summary: "LuckyMinus20",
		Description: "AES-NI implementation in OpenSSL before 1.0.1t and 1.0.2 before 1.0.2h allows remote attackers to obtain sensitive" +
			"cleartext information",
		Score:           report.SeverityThresholdMedium,
		ImpactDetails:   "Allows remote attackers to obtain sensitive cleartext information via a padding-oracle attack against an AES CBC session",
		References:      []string{"https://blog.cloudflare.com/yet-another-padding-oracle-in-openssl-cbc-ciphersuites/"},
		Recommendations: []string{"Upgrade OpenSSL to, at least, 1.0.2h or 1.0.1t"},
	}
)

func main() {
	run := func(ctx context.Context, target, assetType, optJSON string, state checkstate.State) (err error) {
		logger := check.NewCheckLog(checkName)

		if target == "" {
			return errors.New("check target missing")
		}

		isReachable, err := helpers.IsReachable(target, assetType, nil)
		if err != nil {
			logger.Warnf("Can not check asset reachability: %v", err)
		}
		if !isReachable {
			return checkstate.ErrAssetUnreachable
		}

		res, _ := LuckyMinus20.Test(target)
		if res {
			state.AddVulnerabilities(luckyVuln)
		}
		return nil
	}
	c := check.NewCheckFromHandler(checkName, run)
	c.RunAndServe()
}
