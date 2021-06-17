package main

import "errors"

var (
	// ErrNoBurpAPIToken is returned by the check when the Burp api token is
	// not defined.
	ErrNoBurpAPIToken = errors.New("BURP_API_TOKE env var must be set")

	// ErrNoBurpAPIEndPoint is returned by the check when the Burp API endpoint
	// is not defined.
	ErrNoBurpBaseURL = errors.New("BURP_BASE_URL env var must be set")

	// ErrNoBurpScanConfig defines the error returned by the check when no
	// config for the Burp scan has been defined.
	ErrNoBurpScanConfig = errors.New("BURP_SCAN_CONFIG env var must be set")
)
