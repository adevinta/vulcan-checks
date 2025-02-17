/*
Copyright 2022 Adevinta
*/

// Package intel provides a client to interact with the Intel API.
package intel

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
)

// ErrAssetDoesNotExist is returned by the [Client] when there is no info
// about the asset in the Security Graph.
var ErrAssetDoesNotExist = errors.New("asset does not exist in the Security Graph")

// HTTPStatusError is returned by the method [IntelAPIClient.BlastRadius] when
// it receives a response with a status code different to 200.
type HTTPStatusError struct {
	Status int    `json:"-"`
	Msg    string `json:"msg"`
}

func (h HTTPStatusError) Error() string {
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
	Score float64 `json:"score"`
	// Metadata contains information about how a blast radius was calculated.
	Metadata string `json:"metadata"`
}

// Client allows to communicates with Intel API exposed by the Security Graph.
type Client struct {
	httpcli  http.Client
	endpoint *url.URL
}

// NewClient returns an [Client] that uses the given config parameters.
func NewClient(baseURL string, insecure bool) (*Client, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: insecure},
	}
	hClient := http.Client{Transport: tr}
	endpoint, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid intel API endpoint url %s: %w", endpoint, err)
	}
	client := &Client{
		httpcli:  hClient,
		endpoint: endpoint,
	}
	return client, nil
}

func (i *Client) urlBlastRadius(identifier string, assetType string) string {
	u := i.endpoint.JoinPath("/v1/blast-radius")
	q := u.Query()
	if identifier != "" {
		q.Set("asset_identifier", identifier)
	}
	if assetType != "" {
		q.Set("asset_type", assetType)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// BlastRadius calls the blast radius endpoint of the Intel API using the given
// parameters.
func (i *Client) BlastRadius(req BlastRadiusRequest) (BlastRadiusResponse, error) {
	u := i.urlBlastRadius(req.AssetIdentifier, req.AssetType)
	resp, err := i.httpcli.Get(u)
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
	if resp.StatusCode == http.StatusNotFound {
		return BlastRadiusResponse{}, ErrAssetDoesNotExist
	}

	intelAPIErr := HTTPStatusError{Status: resp.StatusCode}
	// Some errors can also return a json payload with extended info.
	if resp.Header.Get("Content-Type") == "application/json" {
		err := json.NewDecoder(resp.Body).Decode(&intelAPIErr)
		if err != nil {
			intelAPIErr.Msg = fmt.Sprintf("error decoding extended info from the response %v", err)
		}
	}
	return BlastRadiusResponse{}, &intelAPIErr
}
