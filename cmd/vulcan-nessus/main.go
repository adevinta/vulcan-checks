package main

import (
	"os"

	check "github.com/adevinta/vulcan-check-sdk"
)

var (
	checkName = "vulcan-nessus"
	logger    = check.NewCheckLog(checkName)
)

type options struct {
	DelayRange      int   `json:"delay_range"`
	PollingInterval int   `json:"polling_interval"`
	BasicAuth       bool  `json:"basic_auth"`
	Delete          *bool `json:"delete"`
}

func main() {
	logger.Infof("NESSUS_ENDPOINT: [%s]", os.Getenv("NESSUS_ENDPOINT"))
	logger.Infof("NESSUS_USERNAME: [%s]", os.Getenv("NESSUS_USERNAME"))
	logger.Infof("NESSUS_POLICY_ID: [%s]", os.Getenv("NESSUS_POLICY_ID"))
	nessusRunner := &runner{}
	c := check.NewCheck(checkName, nessusRunner)
	c.RunAndServe()
}
