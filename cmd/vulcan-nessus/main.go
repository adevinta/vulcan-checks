/*
Copyright 2019 Adevinta
*/

package main

import (
	check "github.com/adevinta/vulcan-check-sdk"
)

const checkName = "vulcan-nessus"

type options struct {
	DelayRange      int   `json:"delay_range"`
	PollingInterval int   `json:"polling_interval"`
	BasicAuth       bool  `json:"basic_auth"`
	Delete          *bool `json:"delete"`
}

func main() {
	nessusRunner := &runner{}
	c := check.NewCheck(checkName, nessusRunner)
	c.RunAndServe()
}
