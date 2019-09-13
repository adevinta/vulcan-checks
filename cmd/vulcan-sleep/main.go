package main

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/adevinta/vulcan-check-sdk"
	"github.com/adevinta/vulcan-check-sdk/state"
)

var (
	checkName = "vulcan-sleep"
	logger    = check.NewCheckLog(checkName)
)

type options struct {
	SleepTime int `json:"sleep_time"`
}

func main() {
	c := check.NewCheckFromHandler(checkName, run)
	c.RunAndServe()
}

func run(ctx context.Context, target string, optJSON string, state state.State) (err error) {
	var opt options
	logger.Printf("Starting the %v check", checkName)
	logger.Printf("Validating params. Target: %v Options: %v ...", target, optJSON)

	if optJSON == "" {
		return errors.New("error: missing sleep time")
	}
	if err := json.Unmarshal([]byte(optJSON), &opt); err != nil {
		return err
	}
	if opt.SleepTime <= 0 {
		return errors.New("error: missing or 0 sleep time")
	}
	logger.Debugf("going sleep %v seconds.", strconv.Itoa(opt.SleepTime))

	select {
	case <-time.After(time.Duration(opt.SleepTime) * time.Second):
		logger.Debugf("slept successfully %s seconds", strconv.Itoa(opt.SleepTime))
	case <-ctx.Done():
		logger.Info("Check aborted")
	}
	return ctx.Err()
}
