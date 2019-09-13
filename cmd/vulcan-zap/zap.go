package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	report "github.com/adevinta/vulcan-report"
)

func hostnameToURL(hostname string, port int) url.URL {
	u := url.URL{}
	u.Path = "//"

	if port != 0 {
		u.Host = fmt.Sprintf("%v:%v", hostname, port)
	} else {
		u.Host = hostname
	}

	for _, scheme := range []string{"https", "http"} {
		u.Scheme = scheme

		timeout := 10 * time.Second
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}

		client := &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
			Transport: tr,
			Timeout:   timeout,
		}

		_, err := client.Get(u.String())
		if err != nil {
			continue
		}

		return u
	}

	return url.URL{}
}

func riskToScore(risk string) float32 {
	switch risk {
	case "Informational":
		return float32(report.SeverityNone)
	case "Low":
		return float32(report.SeverityLow)
	case "Medium":
		return float32(report.SeverityMedium)
	case "High":
		return float32(report.SeverityHigh)
	}

	return float32(report.SeverityNone)
}

func processAlert(a map[string]interface{}) (report.Vulnerability, error) {
	var ok bool
	var err error

	v := report.Vulnerability{}

	v.Summary, ok = a["name"].(string)
	if !ok {
		return report.Vulnerability{}, errors.New("Error retrieving vulnerability summary.")
	}

	v.Description, ok = a["description"].(string)
	if !ok {
		return report.Vulnerability{}, fmt.Errorf("Error retrieving description for \"%v\".", v.Summary)
	}

	v.Details, ok = a["other"].(string)
	if !ok {
		return report.Vulnerability{}, fmt.Errorf("Error retrieving details for \"%v\".", v.Summary)
	}

	recommendations, ok := a["solution"].(string)
	if !ok {
		return report.Vulnerability{}, fmt.Errorf("Error retrieving recommendations for \"%v\".", v.Summary)
	}
	v.Recommendations = strings.Split(recommendations, "\n")

	references, ok := a["reference"].(string)
	if !ok {
		return report.Vulnerability{}, fmt.Errorf("Error retrieving references for \"%v\".", v.Summary)
	}
	v.References = strings.Split(references, "\n")

	risk, ok := a["risk"].(string)
	if !ok {
		return report.Vulnerability{}, fmt.Errorf("Error retrieving score for \"%v\".", v.Summary)
	}
	v.Score = riskToScore(risk)

	cweID, ok := a["cweid"].(string)
	if !ok {
		return report.Vulnerability{}, fmt.Errorf("Error retrieving CWE ID for \"%v\".", v.Summary)
	}
	cweIDInt, err := strconv.Atoi(cweID)
	if err != nil {
		return report.Vulnerability{}, fmt.Errorf("Error converting CWE ID for \"%v\".", v.Summary)
	}
	v.CWEID = uint32(cweIDInt)

	resMethod, ok := a["method"].(string)
	if !ok {
		return report.Vulnerability{}, fmt.Errorf("Error retrieving method for \"%v\".", v.Summary)
	}

	resURL, ok := a["url"].(string)
	if !ok {
		return report.Vulnerability{}, fmt.Errorf("Error retrieving URL for \"%v\".", v.Summary)
	}

	resParam, ok := a["param"].(string)
	if !ok {
		return report.Vulnerability{}, fmt.Errorf("Error retrieving parameter for \"%v\".", v.Summary)
	}

	resAttack, ok := a["attack"].(string)
	if !ok {
		return report.Vulnerability{}, fmt.Errorf("Error retrieving attack for \"%v\".", v.Summary)
	}

	resEvidence, ok := a["evidence"].(string)
	if !ok {
		return report.Vulnerability{}, fmt.Errorf("Error retrieving evidence for \"%v\".", v.Summary)
	}

	v.Resources = []report.ResourcesGroup{
		report.ResourcesGroup{
			Name: "Affected Requests",
			Header: []string{
				"Method",
				"URL",
				"Parameter",
				"Attack",
				"Evidence",
			},
			Rows: []map[string]string{
				map[string]string{
					"Method":    resMethod,
					"URL":       resURL,
					"Parameter": resParam,
					"Attack":    resAttack,
					"Evidence":  resEvidence,
				},
			},
		},
	}

	return v, nil
}
