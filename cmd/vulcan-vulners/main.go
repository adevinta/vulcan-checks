/*
Copyright 2021 Adevinta
*/

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"
	"sort"
	"strings"

	"github.com/sirupsen/logrus"

	check "github.com/adevinta/vulcan-check-sdk"
	"github.com/adevinta/vulcan-check-sdk/helpers"
	"github.com/adevinta/vulcan-check-sdk/helpers/nmap"
	checkstate "github.com/adevinta/vulcan-check-sdk/state"
	report "github.com/adevinta/vulcan-report"
	gonmap "github.com/lair-framework/go-nmap"
)

const (
	defaultTiming = 4

	apiVersion      = "1.4"
	apiEndpointBase = "https://vulners.com/api/v3/burp/software/"
	apiEndpointFmt  = "%s?software=%s&version=%s&type=%s"

	// From https://cpe.mitre.org/specification/2.2/cpe-specification_2.2.pdf
	// page 28.
	cpeRegexStr = `^cpe:/[aho]?:[._\-~%0-9A-Za-z]*(?::[._\-~%0-9A-Za-z]*){0,5}$`
)

type options struct {
	// Nmap timing parameter.
	Timing int `json:"timing"`
}

var (
	checkName = "vulcan-vulners"

	vulnersVuln = report.Vulnerability{
		Summary:     "Multiple vulnerabilities in %s",
		Description: "One or more vulnerabilities were detected in %s.",
		Score:       report.SeverityThresholdNone,
		Recommendations: []string{
			"If possible, restrict network access to the service.",
			"Check if the service has available security updates and apply them.",
			"When in doubt, check the resources linked below.",
		},
	}

	logger   *logrus.Entry
	cpeRegex *regexp.Regexp
)

func apiEndpoint(s, v, t string) string {
	return fmt.Sprintf(apiEndpointFmt, apiEndpointBase, s, v, t)
}

type vulnersResponse struct {
	Result string `json:"result"`
	Data   struct {
		Search []struct {
			Index  string  `json:"_index"`
			Type   string  `json:"_type"`
			ID     string  `json:"_id"`
			Score  float64 `json:"_score"`
			Source struct {
				Lastseen       string `json:"lastseen"`
				BulletinFamily string `json:"bulletinFamily"`
				Description    string `json:"description"`
				Modified       string `json:"modified"`
				ID             string `json:"id"`
				Href           string `json:"href"`
				Published      string `json:"published"`
				Title          string `json:"title"`
				Type           string `json:"type"`
				CVSS           struct {
					Score  float64 `json:"score"`
					Vector string  `json:"vector"`
				} `json:"cvss"`
			} `json:"_source"`
		} `json:"search"`
		Total int `json:"total"`
	} `json:"data"`
}

func severity(score float32) string {
	r := report.RankSeverity(score)

	switch r {
	case report.SeverityNone:
		return "Info"
	case report.SeverityLow:
		return "Low"
	case report.SeverityMedium:
		return "Medium"
	case report.SeverityHigh:
		return "High"
	case report.SeverityCritical:
		return "Critical"
	default:
		return "N/A"
	}
}

type vulnersFinding struct {
	Score     float32
	Resources report.ResourcesGroup
}

// buildVulnersFinding builds a vulners finding querying the vulners.com API. The
// resources of the finding contain the CVE'S found for the software component.
// The Score of the finding contains the highest score found in the all the
// CVE's.
func buildVulnersFinding(s, v, t string) (*vulnersFinding, error) {
	client := &http.Client{}
	endpoint := apiEndpoint(s, v, t)
	logger.Debugf("Using %s as endpoint", endpoint)

	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("can not create request: %w", err)
	}
	req.Header.Add("User-Agent", fmt.Sprintf("Vulners NMAP Plugin %s", apiVersion))

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("can not execute request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("wrong status code: got %d, want %d", resp.StatusCode, http.StatusOK)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading the reponse: %w", err)
	}

	logger.Debugf("Response from vulners.com API: %s", body)

	var b vulnersResponse
	if err := json.Unmarshal(body, &b); err != nil {
		return nil, fmt.Errorf("error decoding the reponse: %w", err)
	}

	if b.Result != "OK" {
		logger.Infof("result field in reponse is different than OK: %v", b.Result)
		return nil, nil
	}

	gr := report.ResourcesGroup{
		Name: "Findings",
		Header: []string{
			"CVE",
			"Severity",
			"Score",
			"Link",
		},
	}

	add := false
	var rows []map[string]string
	var score float32
	for _, e := range b.Data.Search {
		// NOTE (julianvilas): for now support just the CVE type. But would be good
		// to evaluate other types.
		if strings.ToLower(e.Source.Type) != "cve" {
			continue
		}

		add = true

		r := map[string]string{
			"CVE":      e.Source.ID,
			"Severity": severity(float32(e.Source.CVSS.Score)),
			"Score":    fmt.Sprintf("%.2f", e.Source.CVSS.Score),
			"Link":     e.Source.Href,
		}
		rows = append(rows, r)

		logger.WithFields(logrus.Fields{"resource": r}).Debug("Resource added")

		// score contains the max score found in all the CVE's of the finding.
		if float32(e.Source.CVSS.Score) > score {
			score = float32(e.Source.CVSS.Score)
		}
	}

	if !add {
		return nil, nil
	}

	// Sort by score and alphabetically.
	sort.Slice(rows, func(i, j int) bool {
		switch {
		case rows[i]["Score"] != rows[j]["Score"]:
			return rows[i]["Score"] > rows[j]["Score"]
		default:
			return rows[i]["CVE"] > rows[j]["CVE"]
		}
	})
	gr.Rows = rows

	f := vulnersFinding{
		Resources: gr,
		Score:     score,
	}
	logger.WithFields(logrus.Fields{"vulnersFindingAdded": f}).Debug("vulners finding added")

	return &f, nil
}

func findingByCPE(CPE string) (*vulnersFinding, error) {
	if !cpeRegex.MatchString(CPE) {
		return nil, fmt.Errorf("the CPE %s doesn't match the regex %s", CPE, cpeRegex)
	}

	parts := strings.Split(CPE, ":")

	// Skip if the type is not 'a' or there is not version.
	if parts[1] != "/a" || len(parts) < 5 || parts[4] == "" {
		logger.Debug("Skipping because of the given CPE")
		return nil, nil
	}

	return buildVulnersFinding(CPE, parts[4], "cpe")
}

func findingByProdVers(s, v, t string) (*vulnersFinding, error) {
	return buildVulnersFinding(s, v, t)
}

func analyzeReport(target string, nmapReport *gonmap.NmapRun) ([]report.Vulnerability, error) {
	type vulnData struct {
		Vuln     report.Vulnerability
		CPEs     map[string]struct{}
		Products map[string]struct{}
	}
	uniqueVulns := map[string]vulnData{}

	for _, host := range nmapReport.Hosts {
		for _, port := range host.Ports {
			logger.Debugf("Port detected: %d/%s", port.PortId, port.Protocol)

			done := false
			for _, cpe := range port.Service.CPEs {
				logger.Debugf("CPE found: %v", cpe)
				done = true
				f, err := findingByCPE(string(cpe))
				if err != nil {
					return nil, err
				}
				if f == nil {
					continue
				}
				summary := fmt.Sprintf(vulnersVuln.Summary, port.Service.Product)
				v, ok := uniqueVulns[summary]
				if !ok {
					v.Vuln = report.Vulnerability{
						Summary:         summary,
						Description:     fmt.Sprintf(vulnersVuln.Description, port.Service.Product),
						Recommendations: vulnersVuln.Recommendations,
					}
					v.CPEs = map[string]struct{}{}
					uniqueVulns[summary] = v
				}
				if _, ok := v.CPEs[string(cpe)]; !ok {
					v.CPEs[string(cpe)] = struct{}{}
					v.Vuln.Resources = append(v.Vuln.Resources, f.Resources)
					uniqueVulns[summary] = v
					if f.Score > v.Vuln.Score {
						v.Vuln.Score = f.Score
					}
				}
				v.Vuln.Details = fmt.Sprintf(
					"%sHost: %s\nPort: %d/%s\nProduct: %s\nVersion: %s\nCPEs: %v\n\n",
					v.Vuln.Details, host.Hostnames[0].Name, port.PortId, port.Protocol,
					port.Service.Product, port.Service.Version, port.Service.CPEs,
				)
				uniqueVulns[summary] = v
			}
			if done {
				continue
			}

			logger.Debugf("CPE not found, using product (%s) and version (%s) instead", port.Service.Product, port.Service.Version)

			if port.Service.Product == "" || port.Service.Version == "" {
				logger.Debug("Skip: Product or Version are empty")
				continue
			}

			f, err := findingByProdVers(port.Service.Product, port.Service.Version, "software")
			if err != nil {
				return nil, err
			}
			summary := fmt.Sprintf(vulnersVuln.Summary, port.Service.Product)
			v, ok := uniqueVulns[summary]
			if !ok {
				v.Vuln = report.Vulnerability{
					Summary:         summary,
					Description:     fmt.Sprintf(vulnersVuln.Description, port.Service.Product),
					Score:           f.Score,
					Recommendations: vulnersVuln.Recommendations,
				}
				v.CPEs = map[string]struct{}{}
				uniqueVulns[summary] = v
			}
			productID := port.Service.Product + port.Service.Version
			if _, ok := v.Products[productID]; !ok {
				v.CPEs[productID] = struct{}{}
				v.Vuln.Resources = append(v.Vuln.Resources, f.Resources)
				uniqueVulns[summary] = v
				if f.Score > v.Vuln.Score {
					v.Vuln.Score = f.Score
				}
			}
			v.Vuln.Details = fmt.Sprintf(
				"%sHost: %s\nPort: %d/%s\nProduct: %s\nVersion: %s\nCPEs: %v\n\n",
				v.Vuln.Details, host.Hostnames[0].Name, port.PortId, port.Protocol,
				port.Service.Product, port.Service.Version, port.Service.CPEs,
			)
			uniqueVulns[summary] = v
		}
	}
	var vulns []report.Vulnerability
	for _, v := range uniqueVulns {
		vulns = append(vulns, v.Vuln)
	}
	return vulns, nil
}

func run(ctx context.Context, target, assetType, optJSON string, state checkstate.State) (err error) {
	l := check.NewCheckLog(checkName)
	logger = l.WithFields(logrus.Fields{"target": target, "assetType": assetType, "options": optJSON})

	if cpeRegex, err = regexp.Compile(cpeRegexStr); err != nil {
		return fmt.Errorf("regex can not be compiled. regex: %s, error: %v", cpeRegexStr, err)
	}

	var opt options
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

	if opt.Timing == 0 {
		opt.Timing = defaultTiming
	}

	// Scan with version detection.
	nmapParams := map[string]string{
		"-Pn": "",
		"-sV": "",
	}

	nmapRunner := nmap.NewNmapCheck(target, state, opt.Timing, nmapParams)
	nmapReport, _, err := nmapRunner.Run(ctx)
	if err != nil {
		return err
	}

	vulns, err := analyzeReport(target, nmapReport)
	if err != nil {
		return err
	}

	state.AddVulnerabilities(vulns...)

	return nil
}

func main() {
	c := check.NewCheckFromHandler(checkName, run)
	c.RunAndServe()
}
