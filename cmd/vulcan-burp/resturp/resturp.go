package resturp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/cenkalti/backoff/v4"
	log "github.com/sirupsen/logrus"
)

const (
	baseAPIPath    = "/api"
	restAPIPath    = "/v0.1"
	graphQLAPIPath = "/graphql/v1"
)

// Doer contains the methods needed by Resturp in order to make http client
// calls.
type Doer interface {
	Do(*http.Request) (*http.Response, error)
}

func (r *Resturp) doWithRetry(req *http.Request, expectedStatusCode int, statusCodeRiseException bool) (*http.Response, error) {
	var resp *http.Response
	bo := backoff.NewExponentialBackOff()
	bo.MaxElapsedTime = 60 * time.Second
	bo.MaxInterval = 15 * time.Second
	retryCount := 0
	err := backoff.Retry(func() func() error {
		return func() error {
			defer func() {
				if retryCount > 0 {
					r.logger.Warnf("contacting with Burp API. Retry #%d", retryCount)
				}
				retryCount += 1
			}()
			var err error
			resp, err = r.doer.Do(req)
			if err != nil {
				return err
			}
			if resp.StatusCode != expectedStatusCode {
				return ErrUnexpectedStatusCodeReceived
			}
			return nil
		}
	}(), bo)
	if !statusCodeRiseException && err == ErrUnexpectedStatusCodeReceived {
		return resp, nil
	}

	var errTokenRedacted error
	if err != nil {
		errTokenRedacted = errors.New(fmt.Sprint(strings.Replace(err.Error(), r.apiKey, "<REDACTED>", -1)))
	}
	return resp, errTokenRedacted
}

// Resturp is a client for the Burp scanner rest API.
type Resturp struct {
	doer       Doer
	restURL    string
	graphQLURL string
	apiKey     string
	logger     *log.Entry
}

type GraphQLMutationTemplateParams struct {
	OperationName         string
	VariablesInputID      uint
	QueryMutationFunction string
}

type GraphQLQueryTemplateParams struct {
	OperationName string
	QueryFunction string
}

var GraphQLMutationTemplate = `{
		"operationName":"{{.OperationName}}",
		"variables":{
			"input":{
				"id":"{{.VariablesInputID}}"
			}
		},
		"query":"mutation {{.OperationName}}($input: {{.OperationName}}Input!) {\n  {{.QueryMutationFunction}}(input: $input) {\n    id\n    __typename\n  }\n}\n"
	}`

// New returns a ready to use Burp REST client.
// The burpRESTURL must have the form: https://hostname:port.
func New(d Doer, burpBaseURL string, APIKey string, logger *log.Entry) (*Resturp, error) {
	_, err := url.Parse(burpBaseURL)
	if err != nil {
		return nil, err
	}
	return &Resturp{
			doer:       d,
			restURL:    fmt.Sprintf("%s%s/%s%s", burpBaseURL, baseAPIPath, APIKey, restAPIPath),
			graphQLURL: fmt.Sprintf("%s%s", burpBaseURL, graphQLAPIPath),
			apiKey:     APIKey,
			logger:     logger,
		},
		nil
}

func (r *Resturp) getSiteID(ctx context.Context, targetURL string) (uint, error) {
	var parsedID uint
	payload := fmt.Sprintf(`{
        "operationName": "SitesAndFolderInfo",
        "query":"query SitesAndFolderInfo { site_tree {sites { id scope_v2 { start_urls } } } }" 
    }`)

	body, err := r.gDo(ctx, payload)
	if err != nil {
		return 0, err
	}

	var response GetSiteID
	err = json.Unmarshal(body, &response)
	if err != nil {
		return parsedID, err
	}

	// Look for site with matching URL
	for _, site := range response.Data.SiteTree.Sites {
		if site.ScopeV2.StartURLs[0] == targetURL {
			r.logger.Infof("found existing site with ID: %s", site.ID)
			parsedUint64, err := strconv.ParseUint(site.ID, 10, 32)
			if err != nil {
				return parsedID, fmt.Errorf("error parsing site ID: %w", err)
			}
			parsedID = uint(parsedUint64)
			return parsedID, nil
		}
	}

	return parsedID, nil
}

func (r *Resturp) createSite(ctx context.Context, targetURL string) (uint, error) {
	// Create mutation payload with URL in variables
	payload := fmt.Sprintf(`{
        "operationName": "CreateSite",
        "variables": {
            "input": {
                "name": "%s","parent_id": "0","scope_v2": {"start_urls": ["%s"],"protocol_options": "USE_SPECIFIED_PROTOCOLS"},"confirm_permission_to_scan": true}},
        "query": "mutation CreateSite($input: CreateSiteInput!) { create_site(input: $input) { site { id } } }"
    }`, targetURL, targetURL)

	body, err := r.gDo(ctx, payload)
	if err != nil {
		return 0, err
	}

	// Parse response to get site ID
	var response CreateSite
	err = json.Unmarshal(body, &response)
	if err != nil {
		return 0, fmt.Errorf("error parsing response: %w", err)
	}

	if response.Data.CreateSite.Site.ID == "" {
		return 0, fmt.Errorf("no site ID returned in response")
	}

	siteID, err := strconv.ParseUint(response.Data.CreateSite.Site.ID, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("error converting site ID: %w", err)
	}

	r.logger.Infof("site created with Burp site ID [%d]", siteID)
	return uint(siteID), nil
}

// LaunchScan runs a new scan using the specified configurations against the
// given target url. The configurations must exist in the Burp library, for
// instance: "Minimize false positives". It returns the id of the created scan.
func (r *Resturp) LaunchScan(ctx context.Context, targetURL string, configs []string) (uint, error) {
	var siteID uint
	// First check if site exists
	siteID, err := r.getSiteID(ctx, targetURL)
	if err != nil {
		return siteID, fmt.Errorf("error checking for existing site: %w", err)
	}

	if siteID == 0 {
		// Site doesn't exist, create it
		siteID, err = r.createSite(ctx, targetURL)
		if err != nil {
			return siteID, fmt.Errorf("error creating site: %w", err)
		}
	}

	quotedConfigs := make([]string, len(configs))
	for i, s := range configs {
		quotedConfigs[i] = strconv.Quote(s)
	}
	payload := fmt.Sprintf(`{
        "operationName": "CreateScheduleItem",
        "variables": {
            "input": {
                "site_id": %d,"scan_configuration_ids": [%s]}},
        "query": "mutation CreateScheduleItem($input: CreateScheduleItemInput!) { create_schedule_item(input: $input) { schedule_item { id } } }"
    }`, siteID, strings.Join(quotedConfigs, ", "))

	body, err := r.gDo(ctx, payload)
	if err != nil {
		return 0, err
	}
	// Parse response to get scan ID
	var response CreateScan
	err = json.Unmarshal(body, &response)
	if err != nil {
		return 0, fmt.Errorf("error parsing response: %w", err)
	}
	if response.Data.CreateScheduleItem.ScheduleItem.ID == "" {
		return 0, fmt.Errorf("no site ID returned in response")
	}

	scanID, err := strconv.ParseUint(response.Data.CreateScheduleItem.ScheduleItem.ID, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("error converting scan ID: %w", err)
	}

	r.logger.Infof("site created with Burp site ID [%d]", scanID)
	return uint(scanID), nil
}

// GetScanStatus returns the status of a scan.
func (r *Resturp) getScanStatus(ctx context.Context, ID uint) (*ScanStatusGraphQL, error) {
	payload := fmt.Sprintf(`{
        "operationName": "GetScan",
        "variables": {
            "scan_id": "%d"
         },
        "query":"query GetScan ($scan_id: ID!) {scan(id: $scan_id) {id status issues(start: 0, count: 1000) { confidence severity path issue_type { name description_html remediation_html vulnerability_classifications_html references_html } } } }" 
    }`, ID)

	body, err := r.gDo(ctx, payload)
	if err != nil {
		return nil, err
	}

	var response ScanStatusGraphQL
	err = json.Unmarshal(body, &response)
	if err != nil {
		return nil, err
	}
	return &response, nil
}

// GetScanStatus returns the status of a scan.
func (r *Resturp) GetScanStatus(ctx context.Context, ID uint) (*ScanStatusGraphQL, error) {
	//return r.getScanStatusREST(ctx, ID)
	return r.getScanStatus(ctx, ID)
}

func graphQLMutationPayloadGenerator(params GraphQLMutationTemplateParams) (string, error) {
	tmpl := template.Must(template.New("").Parse(GraphQLMutationTemplate))
	var payload bytes.Buffer
	if err := tmpl.Execute(&payload, params); err != nil {
		return "", err
	}
	return payload.String(), nil
}

// DeleteScan deletes the scan with the given id.
func (r *Resturp) DeleteScan(ctx context.Context, ID uint) {
	// TODO: this mutation always fails because the api user doen't have permission to delete scans.
	params := GraphQLMutationTemplateParams{
		OperationName:         "DeleteScan",
		VariablesInputID:      ID,
		QueryMutationFunction: "delete_scan",
	}
	payload, err := graphQLMutationPayloadGenerator(params)
	if err != nil {
		r.logger.Errorf("unable to generate payload for Burp scan ID [%d] report: %s", ID, err)
		return
	}
	_, err = r.gDo(ctx, payload)
	if err != nil {
		r.logger.Errorf("unable to delete Burp scan ID [%d] report: %s", ID, err)
		return
	}
	r.logger.Infof("Burp scan ID [%d] report deleted successfully", ID)
}

// CancelScan cancels the scan with the given id.
func (r *Resturp) CancelScan(ctx context.Context, ID uint) {
	params := GraphQLMutationTemplateParams{
		OperationName:         "CancelScan",
		VariablesInputID:      ID,
		QueryMutationFunction: "cancel_scan",
	}
	payload, err := graphQLMutationPayloadGenerator(params)
	if err != nil {
		r.logger.Errorf("unable to generate payload for Burp scan ID [%d] report: %s", ID, err)
		return
	}
	_, err = r.gDo(ctx, payload)
	if err != nil {
		r.logger.Errorf("unable to cancel Burp scan ID [%d] report: %s", ID, err)
		return
	}
	r.logger.Infof("Burp scan ID [%d] cancelled successfully", ID)
}

func (r *Resturp) gDo(ctx context.Context, payload string) ([]byte, error) {
	var body []byte
	preader := strings.NewReader(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.graphQLURL, preader)
	if err != nil {
		return body, err
	}
	req.Header.Add("authorization", r.apiKey)
	req.Header.Add("content-type", "application/json")
	resp, err := r.doWithRetry(req, http.StatusOK, false)
	if err != nil {
		return body, err
	}
	body, err = io.ReadAll(resp.Body)
	if err != nil {
		return body, err
	}
	if resp.StatusCode != http.StatusOK {
		r.logger.Errorf("unexpected response body: %s", body)
		return body, ErrUnexpectedStatusCodeReceived
	}
	var errorResponse GraphQLErrorResponse
	err = json.Unmarshal(body, &errorResponse)
	if err != nil {
		return body, err
	}
	if len(errorResponse.Errors) > 0 {
		r.logger.Errorf("response error: %+v", errorResponse.Errors)
		return body, ErrGraphQLResponse
	}
	return body, nil
}
