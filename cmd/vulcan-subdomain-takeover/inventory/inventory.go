// Package inventory allows to interact with the [Graph Asset Inventory REST
// API].
//
// [Graph Asset Inventory REST API]: https://github.com/adevinta/graph-asset-inventory-api/blob/master/graph_asset_inventory_api/openapi/graph-asset-inventory-api.yaml
package inventory

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

var (
	// ErrNotFound is returned when an entity cannot be found in the Asset
	// Inventory.
	ErrNotFound = errors.New("not found")

	// Unexpired is the [time.Time] expiration assigned to unexpired
	// entities.
	Unexpired = *strtime("9999-12-12T23:59:59Z")
)

// InvalidStatusError is returned when a call to an endpoint of the Graph Asset
// Inventory did not return the expected status code.
type InvalidStatusError struct {
	Expected []int
	Returned int
}

func (w InvalidStatusError) Error() string {
	return fmt.Sprintf("invalid status response code %v, expected %v", w.Returned, w.Expected)
}

// AssetReq represents the "AssetReq" model as defined by the Graph Asset
// Inventory REST API.
type AssetReq struct {
	Type       string     `json:"type"`
	Identifier string     `json:"identifier"`
	Timestamp  *time.Time `json:"timestamp,omitempty"`
	Expiration time.Time  `json:"expiration"`
}

// AssetResp represents the "AssetResp" model as defined by the Graph Asset
// Inventory REST API.
type AssetResp struct {
	ID         string    `json:"id"`
	Type       string    `json:"type"`
	Identifier string    `json:"identifier"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	Expiration time.Time `json:"expiration"`
}

// Pagination contains the pagination parameters. If the Size field is zero,
// pagination is disabled.
type Pagination struct {
	Page int
	Size int
}

// Client represents a client of the Graph Asset Inventory REST API.
type Client struct {
	endpoint *url.URL
	httpcli  http.Client
}

// NewClient returns a [Client] pointing to the given endpoint (for instance
// https://security-graph-asset-inventory/), and optionally skipping the
// verification of the endpoint server certificate.
func NewClient(endpoint string, insecureSkipVerify bool) (Client, error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: insecureSkipVerify},
	}
	httpcli := http.Client{Transport: tr}

	endpointURL, err := url.Parse(endpoint)
	if err != nil {
		return Client{}, fmt.Errorf("invalid endpoint %s", endpoint)
	}

	cli := Client{
		endpoint: endpointURL,
		httpcli:  httpcli,
	}
	return cli, nil
}

func (cli Client) urlAssets(typ, identifier string, validAt time.Time, pag Pagination) string {
	u := cli.endpoint.JoinPath("/v1/assets")

	q := u.Query()
	if typ != "" {
		q.Set("asset_type", typ)
	}
	if identifier != "" {
		q.Set("asset_identifier", identifier)
	}
	if !validAt.IsZero() {
		q.Set("valid_at", validAt.Format(time.RFC3339))
	}
	if pag.Size != 0 {
		q.Set("page", strconv.Itoa(pag.Page))
		q.Set("size", strconv.Itoa(pag.Size))
	}
	u.RawQuery = q.Encode()

	return u.String()
}

// Assets returns a list of assets filtered by type and identifier. If typ,
// identifier are empty and validAt is zero, no filter is applied. The pag
// parameter controls pagination.
func (cli Client) Assets(typ, identifier string, validAt time.Time, pag Pagination) ([]AssetResp, error) {
	u := cli.urlAssets(typ, identifier, validAt, pag)
	resp, err := cli.httpcli.Get(u)
	if err != nil {
		return nil, fmt.Errorf("HTTP request error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		err := InvalidStatusError{
			Expected: []int{http.StatusOK},
			Returned: resp.StatusCode,
		}
		return nil, err
	}

	var assets []AssetResp
	if err := json.NewDecoder(resp.Body).Decode(&assets); err != nil {
		return nil, fmt.Errorf("invalid response: %w", err)
	}

	return assets, nil
}

// strtime takes a time string with layout RFC3339 and returns the parsed
// [time.Time]. It panics on error and is meant to be used on variable
// initialization.
func strtime(s string) *time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return &t
}
