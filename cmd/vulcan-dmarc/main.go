/*
Copyright 2019 Adevinta
*/

package main

import (
	"context"

	"github.com/sirupsen/logrus"

	check "github.com/adevinta/vulcan-check-sdk"
	"github.com/adevinta/vulcan-check-sdk/helpers"
	checkstate "github.com/adevinta/vulcan-check-sdk/state"
)

const checkName = "vulcan-dmarc"

func main() {
	run := func(ctx context.Context, target, assetType, optJSON string, state checkstate.State) (err error) {
		logger := check.NewCheckLog(checkName)
		logger.WithFields(logrus.Fields{
			"domain": target,
		}).Debug("requesting domain")

		isReachable, err := helpers.IsReachable(target, assetType, nil)
		if err != nil {
			logger.Warnf("Can not check asset reachability: %v", err)
		}
		if !isReachable {
			return checkstate.ErrAssetUnreachable
		}

		// Only test DMARC if the domain have a MX entry on DNS
		if !checkMX(target) {
			return nil
		}

		dmarc := DMARC{target: target}
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
