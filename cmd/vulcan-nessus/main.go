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
	PolicyID        int64 `json:"policy_id"`
	PollingInterval int   `json:"polling_interval"`
	BasicAuth       bool  `json:"basic_auth"`
	Delete          bool  `json:"delete"`
}

func main() {
	logger.Infof("NESSUS_ENDPOINT: [%s]", os.Getenv("NESSUS_ENDPOINT"))
	logger.Infof("NESSUS_USERNAME: [%s]", os.Getenv("NESSUS_USERNAME"))
	nessusRunner := &runner{}
	c := check.NewCheck(checkName, nessusRunner)
	c.RunAndServe()
}
