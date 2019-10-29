package main

import (
	"context"

	"github.com/sirupsen/logrus"

	check "github.com/adevinta/vulcan-check-sdk"
	"github.com/adevinta/vulcan-check-sdk/state"
)

var (
	checkName = "vulcan-snyk"
	logger    = check.NewCheckLog(checkName)
)

func main() {
	run := func(ctx context.Context, target string, optJSON string, state state.State) (err error) {
		logger.WithFields(logrus.Fields{
			"repository": target,
		}).Debug("testing repository")

		// TODO: Run Snyk CLI

		return nil
	}
	c := check.NewCheckFromHandler(checkName, run)

	c.RunAndServe()
}
