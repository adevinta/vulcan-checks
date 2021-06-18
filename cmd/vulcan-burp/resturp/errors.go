package resturp

import "errors"

var (
	// ErrUnexpectedStatusCodeReceived is returned when a http request
	// response does not match expected status code.
	ErrUnexpectedStatusCodeReceived = errors.New("unexpected status code received")

	// ErrGraphQLResponse is returned when a http request to the Burp GraphQL
	// API respond with a formatted error.
	ErrGraphQLResponse = errors.New("GraphQL API error response received")

	// ErrNoLocationHeader is returned when creating a Burp scan and
	// the scan ID is available in the location header response.
	ErrNoLocationHeader = errors.New("no location header received")
)
