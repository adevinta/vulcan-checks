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
	"github.com/adevinta/vulcan-check-sdk/helpers/nmap"
	"github.com/adevinta/vulcan-check-sdk/state"
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
		Summary:         "Multiple vulnerabilities in %s",
		Description:     "The nmap vulners script has detected one or more vulnerabilities in the target's exposed services.",
		Score:           report.SeverityThresholdNone,
		Recommendations: []string{"Check the resources table to get more details of the findings."},
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

// vulnerabilities retrieves the vulnerabilities affecting a software component from the vulners.com API.
func vulnerabilities(p, s, v, t string) (*report.Vulnerability, error) {
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

	vuln := vulnersVuln

	gr := report.ResourcesGroup{
		Name: "Findings",
		Header: []string{
			"CVE",
			"Score",
			"Link",
		},
	}

	add := false
	var rows []map[string]string
	for _, e := range b.Data.Search {
		// NOTE (julianvilas): for now support just the CVE type. But would be good
		// to evaluate other types.
		if strings.ToLower(e.Source.Type) != "cve" {
			continue
		}

		add = true

		finding := map[string]string{
			"CVE":   e.Source.ID,
			"Score": fmt.Sprintf("%.2f", e.Source.CVSS.Score),
			"Link":  e.Source.Href,
		}
		rows = append(rows, finding)

		logger.WithFields(logrus.Fields{"resource": finding}).Debug("Resource added")

		if float32(e.Source.CVSS.Score) > vuln.Score {
			vuln.Score = float32(e.Source.CVSS.Score)
		}
	}

	if add {
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

		vuln.Resources = append(vuln.Resources, gr)
		logger.WithFields(logrus.Fields{"vulnerability": vuln}).Debug("Vulnerability added")

		return &vuln, nil
	}

	return nil, nil
}

func vulnerabilitiesByCPE(CPE string) (*report.Vulnerability, error) {
	if !cpeRegex.MatchString(CPE) {
		return nil, fmt.Errorf("the CPE %s doesn't match the regex %s", CPE, cpeRegex)
	}

	parts := strings.Split(CPE, ":")

	// Skip if the type is not 'a' or there is not version.
	if parts[1] != "/a" || len(parts) < 5 || parts[4] == "" {
		logger.Debug("Skipping because of the given CPE")
		return nil, nil
	}

	return vulnerabilities(parts[3], CPE, parts[4], "cpe")
}

func vulnerabilitiesByProdVers(s, v, t string) (*report.Vulnerability, error) {
	return vulnerabilities(s, s, v, t)
}

func analyzeReport(target string, nmapReport *gonmap.NmapRun) ([]report.Vulnerability, error) {
	var vulns []report.Vulnerability
	for _, host := range nmapReport.Hosts {
		for _, port := range host.Ports {
			logger.Debugf("Port detected: %d/%s", port.PortId, port.Protocol)

			done := false
			for _, cpe := range port.Service.CPEs {
				logger.Debugf("CPE found: %v", cpe)
				done = true

				v, err := vulnerabilitiesByCPE(string(cpe))
				if err != nil {
					return nil, err
				}

				if v != nil {
					v.Summary = fmt.Sprintf(v.Summary, port.Service.Product)
					v.Details = fmt.Sprintf("Found at port %d/%s", port.PortId, port.Protocol)

					vulns = append(vulns, *v)
				}
			}
			if done {
				continue
			}

			logger.Debugf("CPE not found, using product (%s) and version (%s) instead", port.Service.Product, port.Service.Version)

			if port.Service.Product == "" || port.Service.Version == "" {
				logger.Debug("Skip: Product or Version are empty")
				continue
			}

			v, err := vulnerabilitiesByProdVers(port.Service.Product, port.Service.Version, "software")
			if err != nil {
				return nil, err
			}
			if v != nil {
				v.Summary = fmt.Sprintf(v.Summary, port.Service.Product)
				v.Details = fmt.Sprintf("Found at %d", port.PortId)

				vulns = append(vulns, *v)
			}
		}
	}

	return vulns, nil
}

func run(ctx context.Context, target string, optJSON string, state state.State) (err error) {
	if cpeRegex, err = regexp.Compile(cpeRegexStr); err != nil {
		return fmt.Errorf("regex can not be compiled. regex: %s, error: %v", cpeRegexStr, err)
	}

	var opt options
	if optJSON != "" {
		if err = json.Unmarshal([]byte(optJSON), &opt); err != nil {
			return err
		}
	}

	l := check.NewCheckLog(checkName)
	logger = l.WithFields(logrus.Fields{"target": target, "options": optJSON})

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
