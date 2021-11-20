/*
Copyright 2019 Adevinta
*/

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
	DelayRange                 int   `json:"delay_range"`
	PollingInterval            int   `json:"polling_interval"`
	BasicAuth                  bool  `json:"basic_auth"`
	Delete                     *bool `json:"delete"`
	LocalAgent                 bool
	LocalAgentRedinessTimeout  int `json:"local_timeout"`
	RemoteAgentRedinessTimeout int `json:"remote_timeout"`
}

func main() {
	logger.Infof("NESSUS_ENDPOINT: [%s]", os.Getenv("NESSUS_ENDPOINT"))
	logger.Infof("NESSUS_USERNAME: [%s]", os.Getenv("NESSUS_USERNAME"))
	logger.Infof("NESSUS_POLICY_ID: [%s]", os.Getenv("NESSUS_POLICY_ID"))
	nessusRunner := &runner{}
	lk, present := os.LookupEnv("LINKING_KEY")
	if present && lk != "" {
		nessusRunner.LocalAgent = true
		logger.Infof("%s is set to run as a local managed agent", checkName)
	}
	c := check.NewCheck(checkName, nessusRunner)
	c.RunAndServe()
}
