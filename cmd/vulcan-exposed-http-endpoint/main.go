/*
Copyright 2019 Adevinta
*/

package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strings"

	"github.com/sirupsen/logrus"

	check "github.com/adevinta/vulcan-check-sdk"
	"github.com/adevinta/vulcan-check-sdk/helpers"
	checkstate "github.com/adevinta/vulcan-check-sdk/state"
	"github.com/adevinta/vulcan-checks/cmd/vulcan-exposed-http-endpoint/path"
	report "github.com/adevinta/vulcan-report"
)

/*
Proposed options format:

{
"paths":[
  {"path":"/one", "status":200 , "resp_regex": ".*(Found)."}
 ,
  {"path":"/other","reg_exp": ".*(Found)."}
 ]
}


All fields in a path are optional and are always "AND" evaluated.
If one or more paths are specified then the check will not test the default paths.
If no fields for a path are specified then the check will be positive if the endpoint replies with an http response no mather
the status code.
If no paths are specified the check will test all the paths present in _paths/*.json
*/

// Options defines the options of the check.
type Options struct {
	Paths path.Paths `json:"paths"`
}

var (
	checkName = "vulcan-exposed-http-endpoint"
	// exposedVuln defines the vulnerability that will be returned by the check
	// when one or more paths are exposed.
	exposedVuln = report.Vulnerability{
		Summary:         "Exposed URLs",
		Description:     "Paths that should not be publicly accessible are exposed.",
		ImpactDetails:   `An attacker may be able to interact with functionalities that could harm your system, like admin endpoints or access information that shouldn't be public.`,
		Score:           report.SeverityThresholdHigh,
		Recommendations: []string{"Forbid access to the reported paths."},
		Resources: []report.ResourcesGroup{
			report.ResourcesGroup{
				Name:   "Exposed URLs",
				Header: []string{"URL"},
				Rows:   []map[string]string{},
			},
		},
	}
)

func init() {
	// We don't want to verify the certificates in this checks.
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
}

func exposedURL(l *logrus.Entry, addr *url.URL, paths path.Paths) (*report.Vulnerability, error) {
	resources := []map[string]string{}
	var vuln *report.Vulnerability
	for _, p := range paths {
		r, err := checkPath(l, addr, p)
		if err != nil {
			return nil, err
		}
		if r != nil {
			resources = append(resources, r)
		}
	}
	if len(resources) > 0 {
		vuln = &exposedVuln
		vuln.Resources[0].Rows = resources
	}
	return vuln, nil
}

func checkPath(l *logrus.Entry, addr *url.URL, p path.Path) (map[string]string, error) {
	checkURL := addr.String()
	if !strings.HasSuffix(checkURL, "/") {
		checkURL = checkURL + "/"
	}
	nPath := strings.TrimPrefix(p.Path, "/")
	checkURL = checkURL + nPath
	client := http.DefaultClient
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	resp, err := client.Get(checkURL)
	if err != nil {
		l.Debugf("path not reachable: %s, reason %v", checkURL, err)
		return nil, nil
	}
	defer resp.Body.Close() // nolint
	// We need to decide what checks to apply for current path in the URL.
	// We have 4 cases:
	// 1. No status and no regex specified.
	// 2. Status but no regexp.
	// 3. No status but regexp.
	// 4. Status and regexp.
	status := -1
	regExpr := ""
	if p.Status != nil {
		status = *p.Status
	}
	if p.RegExp != "" {
		regExpr = p.RegExp
	}

	statusOK := true
	// At this point status will be greater that 0 if a status was specified or
	// no status nor a regexp was specified.
	if status >= 0 {
		statusOK = resp.StatusCode == status
	}
	regExpOK := true
	// At this point regExpr will be not empty if a regexp was specified.
	if regExpr != "" {
		regExpOK, err = checkBodyRegExp(resp, regExpr)
		if err != nil {
			return nil, err
		}
	}
	// The check will be positive if one or both conditions were specified and
	// evaluated to true or no condition was specified.
	positive := statusOK && regExpOK
	if positive {
		return map[string]string{"URL": checkURL}, nil
	}
	return nil, nil
}

func checkBodyRegExp(resp *http.Response, exp string) (bool, error) {
	contents, err := httputil.DumpResponse(resp, true)
	fmt.Printf("contents %q", contents)
	if err != nil {
		return false, err
	}
	return regexp.Match(exp, contents)
}

func main() {
	run := func(ctx context.Context, target, assetType, optJSON string, state checkstate.State) (err error) {
		logger := check.NewCheckLog(checkName)
		logger = logger.WithFields(logrus.Fields{"target": target, "assetType": assetType, "options": optJSON})

		addr, err := url.Parse(target)
		if err != nil {
			return err
		}

		var opt Options
		if optJSON != "" {
			if err = json.Unmarshal([]byte(optJSON), &opt); err != nil {
				return err
			}
		}

		isReachable, err := helpers.IsReachable(target, assetType, nil)
		if err != nil {
			logger.Warnf("Can not check asset reachability: %v", err)
		}
		if !isReachable {
			return checkstate.ErrAssetUnreachable
		}

		paths := opt.Paths
		if len(paths) == 0 {
			defaultPaths, err := path.ReadDefault()
			if err != nil {
				return err
			}
			paths = *defaultPaths
		}
		vuln, err := exposedURL(logger, addr, paths)
		if err != nil {
			return err
		}
		if vuln != nil {
			state.AddVulnerabilities(*vuln)
		}
		return nil
	}

	c := check.NewCheckFromHandler(checkName, run)
	c.RunAndServe()
}
