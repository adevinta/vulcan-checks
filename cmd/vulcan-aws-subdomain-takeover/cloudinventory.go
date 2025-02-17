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
	"text/template"
)

// CloudInventory is a client to interact with the CloudInventory service.
type CloudInventory struct {
	client      *http.Client
	token       string
	endpointTpl *template.Template
}

// NewCloudInventory creates a new CloudInventory object.
func NewCloudInventory(token string, endpoint string) (*CloudInventory, error) {
	t, err := template.New("isInInventory").Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("parsing endpoint template: %w", err)
	}
	return &CloudInventory{
		client:      &http.Client{},
		token:       token,
		endpointTpl: t,
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
		return false, err
	}
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("xc-token", ci.token)
	res, err := ci.client.Do(req)
	if err != nil {
		return false, err
	}
	defer res.Body.Close()

	resBody, err := io.ReadAll(res.Body)
	if err != nil {
		return false, fmt.Errorf("reading response body: %w", err)
	}

	if res.StatusCode >= http.StatusOK && res.StatusCode < http.StatusMultipleChoices {
		if string(resBody) == "{}" {
			return false, nil
		}
		return true, nil
	} else if res.StatusCode == http.StatusNotFound {
		return false, nil
	}
	return false, fmt.Errorf("CloudInventory returned %s", res.Status)
}
