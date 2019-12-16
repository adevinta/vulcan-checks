package main

import (
	"errors"
	"net/url"
	"strings"
)

// parseTarget parses a target string and returns a organization name and repository name.
// e.g.: parseTarget("github.com/adevinta/vulcan-checks") will return "adevinta" as organisation name
// and "vulcan-checks" and repository name.
func parseTarget(target string) (*string, *string, error) {
	if target == "" {
		return nil, nil, errors.New("check target missing")
	}

	// Parse the target string to a url.URL struct.
	targetURL, err := url.Parse(target)
	if err != nil {
		return nil, nil, err
	}

	// Path will be used to build Organization name and Repository Name:
	// Example:
	// targetURL = github.com/adevinta/vulcan-checks
	// path = /adevinta/vulcan-checks
	path := targetURL.Path

	// Split path using "/" as separator.
	slices := strings.Split(path, "/")
	organizationName := slices[1]
	repositoryName := slices[2]

	return &organizationName, &repositoryName, nil
}
