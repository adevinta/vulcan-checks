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
	"strings"
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
	client       *http.Client
	headers      []string
	notFoundBody string
	endpointTpl  *template.Template
}

// NewCloudInventory creates a new CloudInventory object.
func NewCloudInventory(endpoint string, headers []string, notFoundBody string) (*CloudInventory, error) {
	t, err := template.New("isInInventory").Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("parsing endpoint template: %w", err)
	}
	return &CloudInventory{
		client:       &http.Client{},
		headers:      headers,
		notFoundBody: notFoundBody,
		endpointTpl:  t,
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
	if err = addHeaders(req, ci.headers); err != nil {
		return false, fmt.Errorf("adding headers: %w", err)
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
		if string(resBody) == ci.notFoundBody {
			return false, nil
		}
		return true, nil
	} else if res.StatusCode == http.StatusNotFound {
		return false, nil
	}
	return false, fmt.Errorf("%w: %s", ErrResponseError, res.Status)
}

func addHeaders(req *http.Request, headers []string) error {
	for _, h := range headers {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) != 2 {
			return fmt.Errorf("%w: %s", ErrInvalidHeader, h)
		}
		req.Header.Add(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
	}
	return nil
}
