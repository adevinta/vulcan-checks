package main

import "errors"

var (
	// ErrNoBurpAPIToken is returned by the check when the Burp api token is
	// not defined.
	ErrNoBurpAPIToken = errors.New("BURP_API_TOKEN env var must be set")

	// ErrNoBurpAPIEndPoint is returned by the check when the Burp API endpoint
	// is not defined.
	ErrNoBurpBaseURL = errors.New("BURP_BASE_URL env var must be set")
)
