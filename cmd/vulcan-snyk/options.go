package main

import (
	"encoding/json"
	"errors"
)

type options struct {
	// BaseURL is the URL of the remote server where the scanned repositories are hosted
	// Example: github.com
	BaseURL string `json:"base_url"`

	// OrganizationNameToSnykID contains a mapping between the remote server <ORGANIZATION_NAME>
	// and the respective ORG ID in Snyk.
	//
	// Example:
	// If we add all repositories from "github.com/adevinta" to a Snyk org with ID "442dd8d2-7a03-46a4-8ec6-d6cd63817f2e"
	// then the mapping will be:
	// - "adevinta": "442dd8d2-7a03-46a4-8ec6-d6cd63817f2e"
	OrganizationNameToSnykID map[string]string `json:"organization_name_to_snyk_id"`
}

func parseOptions(optJSON string) (*options, error) {
	if len(optJSON) == 0 {
		return nil, errors.New("options string is empty")
	}

	var options options
	err := json.Unmarshal([]byte(optJSON), &options)
	if err != nil {
		return nil, errors.New("unable to parse options as JSON")
	}

	if options.BaseURL == "" {
		return nil, errors.New("options.base_url is empty")
	}

	return &options, nil
}
