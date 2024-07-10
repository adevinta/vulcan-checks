package main

import (
	"context"
	"detectify"
	"fmt"

	check "github.com/adevinta/vulcan-check-sdk"
	checkstate "github.com/adevinta/vulcan-check-sdk/state"
)

var (
	checkName = "vulcan-detectify"
	logger    = check.NewCheckLog(checkName)
)

func main() {

	run := func(ctx context.Context, target, assetType, optJSON string, state checkstate.State) (err error) {
		logger.Printf("Starting the %v check", checkName)

		detectifyRunError := detectify.Run(ctx, target, state)

		if detectifyRunError != nil {
			logger.Println(fmt.Sprintf("[!] detectifyRunError: %s", detectifyRunError.Error()))
			return detectifyRunError
		}

		return nil
	}
	c := check.NewCheckFromHandler(checkName, run)

	c.RunAndServe()

}
