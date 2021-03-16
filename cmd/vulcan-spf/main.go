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

var (
	checkName = "vulcan-spf"
	logger    = check.NewCheckLog(checkName)
)

func main() {
	run := func(ctx context.Context, target, assetType, optJSON string, state checkstate.State) (err error) {
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
