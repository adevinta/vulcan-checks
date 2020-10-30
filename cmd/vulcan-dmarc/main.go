package main

import (
	"context"

	"github.com/sirupsen/logrus"

	check "github.com/adevinta/vulcan-check-sdk"
	"github.com/adevinta/vulcan-check-sdk/state"
)

var (
	checkName = "vulcan-dmarc"
	logger    = check.NewCheckLog(checkName)
)

func main() {
	run := func(ctx context.Context, target, targetType string, optJSON string, state state.State) (err error) {
		logger.WithFields(logrus.Fields{
			"domain": target,
		}).Debug("requesting domain")

		// Only test DMARC if the domain have a MX entry on DNS
		if !checkMX(target) {
			return nil
		}

		dmarc := DMARC{}
		if dmarc.parse(target) {
			dmarc.evaluate()
		}

		if len(dmarc.vulnerabilities) > 0 {
			for _, vulnerability := range dmarc.vulnerabilities {
				state.AddVulnerabilities(vulnerability)
			}
		}

		logger.WithFields(logrus.Fields{
			"dmarc_response": dmarc,
		}).Debug("response recieved")

		return nil
	}

	c := check.NewCheckFromHandler(checkName, run)

	c.RunAndServe()
}
