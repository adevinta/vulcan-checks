/*
Copyright 2021 Adevinta
*/

package main

import (
	check "github.com/adevinta/vulcan-check-sdk"
)

var (
	checkName = "vulcan-burp"
	logger    = check.NewCheckLog(checkName)
)

// Options defines the possible options to be received by the check.
type Options struct {
	ScanID         uint `json:"scan_id"`
	SkipDeleteScan bool `json:"skip_delete_scan"`
}

func main() {
	r := &runner{}
	c := check.NewCheck(checkName, r)
	c.RunAndServe()
}
