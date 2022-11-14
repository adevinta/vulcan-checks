/*
Copyright 2022 Adevinta
*/

package main

import (
	"os"

	check "github.com/adevinta/vulcan-check-sdk"
)

var (
	checkName = "vulcan-tenable"
	logger    = check.NewCheckLog(checkName)
)

type options struct {
	AssetTag  string `json:"asset_tag"` // Example: 'provider:vulcan'.
	BasicAuth bool   `json:"basic_auth"`
}

func main() {
	logger.Infof("NESSUS_ENDPOINT: [%s]", os.Getenv("NESSUS_ENDPOINT"))
	logger.Infof("NESSUS_USERNAME: [%s]", os.Getenv("NESSUS_USERNAME"))
	tenableRunner := &runner{}
	c := check.NewCheck(checkName, tenableRunner)
	c.RunAndServe()
}
