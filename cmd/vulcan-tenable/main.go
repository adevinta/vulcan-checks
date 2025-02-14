/*
Copyright 2022 Adevinta
*/

package main

import (
	check "github.com/adevinta/vulcan-check-sdk"
)

var checkName = "vulcan-tenable"

type options struct {
	AssetTag  string `json:"asset_tag"` // Example: 'provider:vulcan'.
	BasicAuth bool   `json:"basic_auth"`
}

func main() {
	tenableRunner := &runner{}
	c := check.NewCheck(checkName, tenableRunner)
	c.RunAndServe()
}
