package main

import (
	"context"

	"github.com/sirupsen/logrus"

	check "github.com/adevinta/vulcan-check-sdk"
	"github.com/adevinta/vulcan-check-sdk/state"
)

var (
	checkName = "vulcan-spf"
	logger    = check.NewCheckLog(checkName)
)

func main() {
	run := func(ctx context.Context, target, targetType string, optJSON string, state state.State) (err error) {
		logger.WithFields(logrus.Fields{
			"domain": target,
		}).Debug("requesting domain")

		// Perform the DNS query for SPF records.
		spf := SPF{}
		if spf.parse(target) {
			spf.countDNSLookUps()
			spf.evaluate()
		}

		if len(spf.vulnerabilities) > 0 {
			state.AddVulnerabilities(spf.vulnerabilities...)
		}

		logger.WithFields(logrus.Fields{
			"spf_response": spf,
		}).Debug("response recieved")

		return nil
	}
	c := check.NewCheckFromHandler(checkName, run)

	c.RunAndServe()
}
