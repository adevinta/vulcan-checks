package utils

import (
	check "github.com/adevinta/vulcan-check-sdk"
)

const (
	userAgent       = "vulcan-detectify-client/1.0"
	checkName       = "vulcan-detectify"
	debugEnvVarName = "Debug_Traffic_Var"
)

var (
	debugHTTPTraffic = false
	logger           = check.NewCheckLog(checkName)
)

type customErrorVar struct {
	StatusCode int
	Err        error
}
