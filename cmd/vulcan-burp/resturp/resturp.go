package resturp

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"

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

// Resturp is a client for the Burp scanner rest API.
type Resturp struct {
	doer       Doer
	restURL    string
	graphQLURL string
	apiKey     string
	logger     *log.Entry
}

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
		logger:     logger}, nil
}

// LaunchScan runs a new scan using the specified configurations against the
// given target url. The configurations must exist in the Burp library, for
// instance: "Minimize false positives". It returns the id of the created scan.
func (r *Resturp) LaunchScan(targetURL string, configs []string) (uint, error) {
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
	req, err := http.NewRequest(http.MethodPost, sURL, preader)
	if err != nil {
		return 0, err
	}
	resp, err := r.doer.Do(req)
	if err != nil {
		return 0, err
	}

	if resp.StatusCode == http.StatusCreated {
		loc, ok := resp.Header["Location"]
		if !ok || len(loc) < 1 {
			return 0, errors.New("no location header received")
		}
		id, err := strconv.Atoi(loc[0])
		if err != nil {
			return 0, fmt.Errorf("parsing returned task id: %w", err)
		}
		r.logger.Infof("scan created with Burp scan ID [%d]", id)
		uid := uint(id)
		return uid, nil
	}

	if resp.StatusCode == http.StatusBadRequest {
		b, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return 0, err
		}
		scanErr := new(ScanPayloadError)
		err = json.Unmarshal(b, scanErr)
		if err != nil {
			return 0, err
		}
		return 0, scanErr
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return 0, err
	}
	return 0, fmt.Errorf("unexpected status code: %s, response: %s", resp.Status, string(body))
}

// GetScanStatus returns the status of a scan.
func (r *Resturp) GetScanStatus(ID uint) (*ScanStatus, error) {
	sURL := fmt.Sprintf("%s/scan/%d", r.restURL, ID)
	req, err := http.NewRequest(http.MethodGet, sURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := r.doer.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusOK {
		b, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		stat := new(ScanStatus)
		err = json.Unmarshal(b, stat)
		if err != nil {
			return nil, err
		}
		return stat, nil
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return nil, fmt.Errorf("unexpected status code: %s, response: %s", resp.Status, string(body))
}

// GetIssueDefinitions gets the current defined issues in burp.
func (r *Resturp) GetIssueDefinitions() ([]IssueDefinition, error) {
	sURL := fmt.Sprintf("%s/knowledge_base/issue_definitions", r.restURL)
	req, err := http.NewRequest(http.MethodGet, sURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := r.doer.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("unexpected status code: %s, response: %s", resp.Status, string(body))
	}

	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var defs []IssueDefinition
	err = json.Unmarshal(b, &defs)
	if err != nil {
		return nil, err
	}
	return defs, nil
}

// DeleteScan deletes the scan with the given id.
func (r *Resturp) DeleteScan(ID uint) {
	payload := fmt.Sprintf("{\"operationName\":\"DeleteScan\",\"variables\":{\"input\":{\"id\":\"%d\"}},\"query\":\"mutation DeleteScan($input: DeleteScanInput!) {\\n  delete_scan(input: $input) {\\n    id\\n    __typename\\n  }\\n}\\n\"}", ID)
	err := r.gDo(payload)
	if err != nil {
		r.logger.Errorf("unable to delete Burp scan ID [%d] report: %s", ID, err)
		return
	}
	r.logger.Infof("Burp scan ID [%d] report deleted successfully", ID)
}

// CancelScan cancels the scan with the given id.
func (r *Resturp) CancelScan(ID uint) {
	payload := fmt.Sprintf("{\"operationName\":\"CancelScan\",\"variables\":{\"input\":{\"id\":\"%d\"}},\"query\":\"mutation CancelScan($input: CancelScanInput!) {\\n  cancel_scan(input: $input) {\\n    id\\n    __typename\\n  }\\n}\\n\"}", ID)
	err := r.gDo(payload)
	if err != nil {
		r.logger.Errorf("unable to cancel Burp scan ID [%d] report: %s", ID, err)
		return
	}
	r.logger.Infof("Burp scan ID [%d] cancelled successfully", ID)
}

func (r *Resturp) gDo(payload string) error {
	preader := strings.NewReader(string(payload))
	req, err := http.NewRequest(http.MethodPost, r.graphQLURL, preader)
	if err != nil {
		return err
	}
	req.Header.Add("authorization", r.apiKey)
	req.Header.Add("content-type", "application/json")
	resp, err := r.doer.Do(req)
	if err != nil {
		return err
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		r.logger.Errorf("unexpected response body: %s", body)
		return errors.New("unexpected response status code")
	}
	var errorResponse GraphQLErrorResponse
	err = json.Unmarshal(body, &errorResponse)
	if err != nil {
		return err
	}
	if len(errorResponse.Errors) > 0 {
		r.logger.Errorf("response error: %+v", errorResponse.Errors)
		return errors.New("API error response received")
	}
	return nil
}
