/*
Copyright 2025 Adevinta
*/

package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"text/template"
)

var (
	// ErrInvalidHeader is the error returned when the header is invalid.
	ErrInvalidHeader = fmt.Errorf("invalid header")

	// ErrResponseError is the error returned when the response is an error.
	ErrResponseError = fmt.Errorf("response error")
)

// CloudInventory is a client to interact with the CloudInventory service.
type CloudInventory struct {
	client        *http.Client
	headers       map[string]string
	notFoundRegex *regexp.Regexp
	endpointTpl   *template.Template
}

// NewCloudInventory creates a new CloudInventory object.
func NewCloudInventory(endpoint string, headers map[string]string, notFoundRegex *regexp.Regexp) (*CloudInventory, error) {
	t, err := template.New("isInInventory").Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("parsing endpoint template: %w", err)
	}
	return &CloudInventory{
		client:        &http.Client{},
		headers:       headers,
		notFoundRegex: notFoundRegex,
		endpointTpl:   t,
	}, nil
}

// IsIPPublicInInventory checks if an IP is in the CloudInventory.
func (ci *CloudInventory) IsIPPublicInInventory(ctx context.Context, ip string) (bool, error) {
	var tpl bytes.Buffer
	data := struct {
		IP string
	}{
		IP: ip,
	}
	if err := ci.endpointTpl.Execute(&tpl, data); err != nil {
		return false, fmt.Errorf("executing endpoint template: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, tpl.String(), nil)
	if err != nil {
		return false, fmt.Errorf("creating request: %w", err)
	}
	for k, v := range ci.headers {
		if k == "" || v == "" {
			return false, ErrInvalidHeader
		}
		req.Header.Add(k, v)
	}
	res, err := ci.client.Do(req)
	if err != nil {
		return false, fmt.Errorf("making request: %w", err)
	}
	defer res.Body.Close()

	resBody, err := io.ReadAll(res.Body)
	if err != nil {
		return false, fmt.Errorf("reading response body: %w", err)
	}

	if res.StatusCode >= http.StatusOK && res.StatusCode < http.StatusMultipleChoices {
		if ci.notFoundRegex != nil && ci.notFoundRegex.Match(resBody) {
			return false, nil
		}
		return true, nil
	} else if res.StatusCode == http.StatusNotFound {
		return false, nil
	}
	return false, fmt.Errorf("%w: %s", ErrResponseError, res.Status)
}
