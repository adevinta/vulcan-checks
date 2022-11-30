/*
Copyright 2022 Adevinta
*/
// Package securitygraph provides a client to interact with the Intel API.
package securitygraph

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
)

var (
	ErrAssetDoesNotExist = errors.New("asset does not exist in the Security Graph")
	ErrNotEnoughInfo     = errors.New("not enough information for calculating the blast radius")
)

// HttpStatusError is returned by the method [IntelAPIClient.BlastRadius] when
// it receives a response with a status code different to 200.
type HttpStatusError struct {
	Status int    `json:"-"`
	Msg    string `json:"msg"`
}

func (h HttpStatusError) Error() string {
	msg := fmt.Sprintf("invalid http status code received from the intel API: %d, details: %s", h.Status, h.Msg)
	return msg
}

// Config defines the config parameters needed by an [IntelAPIClient].
type Config struct {
	IntelAPI    string `mapstructure:"intel_api"`
	InsecureTLS string `mapstructure:"insecure_tls"`
}

// BlastRadiusRequest defines the parameters required by the blast radius endpoint.
type BlastRadiusRequest struct {
	AssetIdentifier string `json:"asset_identifier" validate:"required" urlquery:"asset_identifier"`
	AssetType       string `json:"asset_type" validate:"required" urlquery:"asset_type"`
}

// BlastRadiusResponse defines the output of a blast radius calculation.
type BlastRadiusResponse struct {
	// Score contains the blast radius score for a given asset.
	Score float32 `json:"score"`
	// Metadata contains information about how a blast radius was calculated.
	Metadata string `json:"string"`
}

// IntelAPIClient allows to communicates with Intel API exposed by the Security Graph.
type IntelAPIClient struct {
	c        http.Client
	endpoint *url.URL
}

// Returns an IntelAPIClient that uses the given config parameters.
func NewIntelAPIClient(baseURL string, insecure bool) (*IntelAPIClient, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
	}
	hClient := http.Client{Transport: tr}
	endpoint, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid intel API endpoint url %s", endpoint)
	}
	client := &IntelAPIClient{
		c:        hClient,
		endpoint: endpoint,
	}
	return client, nil
}

func (i *IntelAPIClient) urlBlastRadius(identifier string, asset_type string) string {
	u := i.endpoint.JoinPath("/v1/blast-radius")
	q := u.Query()
	if identifier != "" {
		q.Set("asset_identifier", identifier)
	}
	if asset_type != "" {
		q.Set("asset_type", asset_type)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// BlastRadius calls the blast radius endpoint of the Intel API using the given
// parameters.
func (i *IntelAPIClient) BlastRadius(req BlastRadiusRequest) (BlastRadiusResponse, error) {
	u := i.urlBlastRadius(req.AssetIdentifier, req.AssetType)
	resp, err := i.c.Get(u)
	if err != nil {
		return BlastRadiusResponse{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		var b BlastRadiusResponse
		err := json.NewDecoder(resp.Body).Decode(&b)
		if err != nil {
			return BlastRadiusResponse{}, fmt.Errorf("invalid response: %w", err)
		}
		return b, nil
	}
	if resp.StatusCode == 404 {
		return BlastRadiusResponse{}, ErrAssetDoesNotExist
	}
	if resp.StatusCode == 422 {
		return BlastRadiusResponse{}, ErrNotEnoughInfo
	}
	intelAPIErr := HttpStatusError{Status: resp.StatusCode}
	// Some errors can also return a json payload with extended info.
	if resp.Header.Get("Content-Type") == "application/json" {
		err := json.NewDecoder(resp.Body).Decode(&intelAPIErr)
		if err != nil {
			intelAPIErr.Msg = fmt.Sprintf("error decoding extended info from the response %v", err)
		}
	}
	return BlastRadiusResponse{}, &intelAPIErr
}
