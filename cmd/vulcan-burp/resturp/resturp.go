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

type GraphQLQueryTemplateParams struct {
	OperationName         string
	VariablesInputID      uint
	QueryMutationFunction string
}

var GraphQLQueryTemplate = `{
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

// LaunchScan runs a new scan using the specified configurations against the
// given target url. The configurations must exist in the Burp library, for
// instance: "Minimize false positives". It returns the id of the created scan.
func (r *Resturp) LaunchScan(ctx context.Context, targetURL string, configs []string) (uint, error) {
	sURL := fmt.Sprintf("%s/scan", r.restURL)
	var sconfigs []ScanConfiguration
	for _, s := range configs {
		sconfigs = append(sconfigs, ScanConfiguration{
			Type: "NamedConfiguration",
			Name: s,
		})
	}
	s := Scan{
		ScanConfigurations: sconfigs,
		Urls:               []string{targetURL},
	}
	payload, err := json.Marshal(s)
	if err != nil {
		return 0, err
	}
	preader := strings.NewReader(string(payload))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, sURL, preader)
	if err != nil {
		return 0, err
	}
	resp, err := r.doWithRetry(req, http.StatusCreated, false)
	if err != nil {
		return 0, err
	}

	if resp.StatusCode == http.StatusCreated {
		loc, ok := resp.Header["Location"]
		if !ok || len(loc) < 1 {
			return 0, ErrNoLocationHeader
		}
		id, err := strconv.Atoi(loc[0])
		if err != nil {
			return 0, fmt.Errorf("parsing returned task id: %w", err)
		}
		r.logger.Infof("scan created with Burp scan ID [%d]", id)
		uid := uint(id)
		return uid, nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, err
	}

	if resp.StatusCode == http.StatusBadRequest {
		scanErr := new(ScanPayloadError)
		err = json.Unmarshal(body, scanErr)
		if err != nil {
			return 0, err
		}
		return 0, scanErr
	}

	return 0, fmt.Errorf("unexpected status code: %s, response: %s", resp.Status, string(body))
}

// GetScanStatus returns the status of a scan.
func (r *Resturp) GetScanStatus(ctx context.Context, ID uint) (*ScanStatus, error) {
	sURL := fmt.Sprintf("%s/scan/%d", r.restURL, ID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, sURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := r.doWithRetry(req, http.StatusOK, false)
	if err != nil {
		return nil, err
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusOK {
		stat := new(ScanStatus)
		err = json.Unmarshal(body, stat)
		if err != nil {
			return nil, err
		}
		return stat, nil
	}

	return nil, fmt.Errorf("unexpected status code: %s, response: %s", resp.Status, string(body))
}

// GetIssueDefinitions gets the current defined issues in burp.
func (r *Resturp) GetIssueDefinitions(ctx context.Context) ([]IssueDefinition, error) {
	sURL := fmt.Sprintf("%s/knowledge_base/issue_definitions", r.restURL)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, sURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := r.doWithRetry(req, http.StatusOK, false)
	if err != nil {
		return nil, err
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %s, response: %s", resp.Status, string(body))
	}

	var defs []IssueDefinition
	err = json.Unmarshal(body, &defs)
	if err != nil {
		return nil, err
	}
	return defs, nil
}

func graphQLPayloadGenerator(params GraphQLQueryTemplateParams) (string, error) {
	tmpl := template.Must(template.New("").Parse(GraphQLQueryTemplate))
	var payload bytes.Buffer
	if err := tmpl.Execute(&payload, params); err != nil {
		return "", err
	}
	return payload.String(), nil
}

// DeleteScan deletes the scan with the given id.
func (r *Resturp) DeleteScan(ctx context.Context, ID uint) {
	params := GraphQLQueryTemplateParams{
		OperationName:         "DeleteScan",
		VariablesInputID:      ID,
		QueryMutationFunction: "delete_scan",
	}
	err := r.gDo(ctx, params)
	if err != nil {
		r.logger.Errorf("unable to delete Burp scan ID [%d] report: %s", ID, err)
		return
	}
	r.logger.Infof("Burp scan ID [%d] report deleted successfully", ID)
}

// CancelScan cancels the scan with the given id.
func (r *Resturp) CancelScan(ctx context.Context, ID uint) {
	params := GraphQLQueryTemplateParams{
		OperationName:         "CancelScan",
		VariablesInputID:      ID,
		QueryMutationFunction: "cancel_scan",
	}
	err := r.gDo(ctx, params)
	if err != nil {
		r.logger.Errorf("unable to cancel Burp scan ID [%d] report: %s", ID, err)
		return
	}
	r.logger.Infof("Burp scan ID [%d] cancelled successfully", ID)
}

func (r *Resturp) gDo(ctx context.Context, params GraphQLQueryTemplateParams) error {
	payload, err := graphQLPayloadGenerator(params)
	if err != nil {
		return err
	}
	preader := strings.NewReader(string(payload))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.graphQLURL, preader)
	if err != nil {
		return err
	}
	req.Header.Add("authorization", r.apiKey)
	req.Header.Add("content-type", "application/json")
	resp, err := r.doWithRetry(req, http.StatusOK, false)
	if err != nil {
		return err
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		r.logger.Errorf("unexpected response body: %s", body)
		return ErrUnexpectedStatusCodeReceived
	}
	var errorResponse GraphQLErrorResponse
	err = json.Unmarshal(body, &errorResponse)
	if err != nil {
		return err
	}
	if len(errorResponse.Errors) > 0 {
		r.logger.Errorf("response error: %+v", errorResponse.Errors)
		return ErrGraphQLResponse
	}
	return nil
}
