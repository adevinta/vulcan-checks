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
)

const basePath = "/v0.1/"

// Doer contains the methods needed by Resturp in order to make http client
// calls.
type Doer interface {
	Do(*http.Request) (*http.Response, error)
}

// Resturp is a client for the Burp scanner rest API.
type Resturp struct {
	doer    Doer
	burpURL *url.URL
}

// New returns a ready to use Burp REST client.
// The burpURL must have the form: https://hostname:port.
func New(d Doer, burpURL string, APIKey string) (*Resturp, error) {
	burp, err := url.Parse(burpURL)
	if err != nil {
		return nil, err
	}
	if APIKey != "" {
		burp.Path = "/" + APIKey
	}
	burp.Path = burp.Path + basePath
	return &Resturp{d, burp}, nil
}

// LaunchScan runs a new scan using the specified configurations against the
// given web url. The configurations must exist in the Burp library, for
// instance: "Minimize false positives". It returns the id of the created scan.
func (r *Resturp) LaunchScan(webURL string, configs []string, user, password string) (uint, error) {
	u := *r.burpURL
	u.Path = u.Path + "scan"
	sURL := u.String()
	var sconfigs []ScanConfiguration
	for _, s := range configs {
		sconfigs = append(sconfigs, ScanConfiguration{
			Type: "NamedConfiguration",
			Name: s,
		})
	}
	s := Scan{
		ScanConfigurations: sconfigs,
		Urls:               []string{webURL},
	}

	if user != "" || password != "" {
		al := ApplicationLogin{
			Username: user,
			Password: password,
		}
		s.ApplicationLogins = []ApplicationLogin{al}
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
	u := *r.burpURL
	id := strconv.Itoa(int(ID))
	u.Path = fmt.Sprintf("%sscan/%s", u.Path, id)
	sURL := u.String()
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
	u := *r.burpURL
	u.Path = fmt.Sprintf("%sknowledge_base/issue_definitions", u.Path)
	sURL := u.String()
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
