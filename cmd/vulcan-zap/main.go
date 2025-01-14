/*
Copyright 2019 Adevinta
*/

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"text/template"

	check "github.com/adevinta/vulcan-check-sdk"
	"github.com/adevinta/vulcan-check-sdk/helpers"
	"github.com/adevinta/vulcan-check-sdk/helpers/command"
	checkstate "github.com/adevinta/vulcan-check-sdk/state"
	report "github.com/adevinta/vulcan-report"
	"github.com/sirupsen/logrus"
)

const (
	checkName   = "vulcan-zap"
	contextName = "target"
)

type options struct {
	Depth    int     `json:"depth"`
	Active   bool    `json:"active"`
	Port     int     `json:"port"`
	MinScore float32 `json:"min_score"`
	// List of active/passive scanners to disable by their identifiers:
	// https://www.zaproxy.org/docs/alerts/
	DisabledScanners           []string `json:"disabled_scanners"`
	DisabledActiveScanners     []string `json:"disabled_active_scanners"`
	IgnoredFingerprintScanners []string `json:"ignored_fingerprint_scanners"`
	MaxSpiderDuration          int      `json:"max_spider_duration"`
	MaxScanDuration            int      `json:"max_scan_duration"` // In minutes
	MaxRuleDuration            int      `json:"max_rule_duration"` // In minutes
	OpenapiUrl                 string   `json:"openapi_url"`
	OpenapiHost                string   `json:"openapi_host"`
}

const configTemplate = `
env:
  contexts:
  - name: Default Context
    urls:
    - "${URL}"
    includePaths:
    - "${URL}.*"
jobs:
{{ if .OpenapiUrl }}
- type: openapi
  parameters:
    apiUrl: "{{ .OpenapiUrl }}"
    targetUrl: "{{ .OpenapiHost }}"
{{ end }}
- type: passiveScan-config
  parameters:
    scanOnlyInScope: true
    maxAlertsPerRule: 5
    enableTags: false
  rules:
{{ range .DisabledScanners }}
  - id: {{ . }}
    threshold: off
{{ end }}
- type: spider
  parameters:
    maxDuration: {{ .MaxSpiderDuration }}
    maxDepth: {{ .Depth }}
- type: spiderAjax
  parameters:
    maxDuration: {{ .MaxSpiderDuration }}
    maxCrawlDepth: {{ .Depth }}
    browserId: htmlunit
- type: passiveScan-wait
  parameters: {}
{{ if .Active }}
- type: activeScan
  parameters:
    maxRuleDurationInMins: {{ .MaxRuleDuration }}
    maxScanDurationInMins: {{ .MaxScanDuration }}
    maxAlertsPerRule: 5
  policyDefinition:
    defaultStrength: medium
    defaultThreshold: medium
    rules:
{{ range .DisabledActiveScanners }}
    - id: {{ . }}
      threshold: off
      strength: default
{{ end }}
{{ end }}
- name: report.json
  type: report
  parameters:
    template: traditional-json
    reportDir: "${ZAPDIR}"
    reportFile: report.json
    displayReport: false
  risks:
  - info
  - low
  - medium
  - high
  confidences:
  - falsepositive
  - low
  - medium
  - high
  - confirmed
`

type Report struct {
	ProgramName string `json:"@programName"`
	Version     string `json:"@version"`
	Generated   string `json:"@generated"`
	Site        []struct {
		Name   string `json:"@name"`
		Host   string `json:"@host"`
		Port   string `json:"@port"`
		Ssl    string `json:"@ssl"`
		Alerts []struct {
			Pluginid   string `json:"pluginid"`
			AlertRef   string `json:"alertRef"`
			Alert      string `json:"alert"`
			Name       string `json:"name"`
			Riskcode   string `json:"riskcode"`
			Confidence string `json:"confidence"`
			Riskdesc   string `json:"riskdesc"`
			Desc       string `json:"desc"`
			Instances  []struct {
				URI       string `json:"uri"`
				Method    string `json:"method"`
				Param     string `json:"param"`
				Attack    string `json:"attack"`
				Evidence  string `json:"evidence"`
				Otherinfo string `json:"otherinfo"`
			} `json:"instances"`
			Count     string `json:"count"`
			Solution  string `json:"solution"`
			Otherinfo string `json:"otherinfo"`
			Reference string `json:"reference"`
			Cweid     string `json:"cweid"`
			Wascid    string `json:"wascid"`
			Sourceid  string `json:"sourceid"`
		} `json:"alerts"`
	} `json:"site"`
}

type pool struct {
	l []int
	m sync.Mutex
}

// Create a pool of 5 ports starting from 13000.
// 5 defines the max number of concurrent scans to allow before a "too many requests error"
var portPool *pool = createPortPool(13000, 5)

func main() {
	run := func(ctx context.Context, target, assetType, optJSON string, state checkstate.State) (err error) {
		logger := check.NewCheckLogFromContext(ctx, checkName)
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

		d, err := os.MkdirTemp(os.TempDir(), "zap-")
		if err != nil {
			return fmt.Errorf("unable to create tmp dir: %w", err)
		}

		defer os.RemoveAll(d)

		tmpl, err := template.New("config").Parse(configTemplate)
		if err != nil {
			panic(err)
		}
		sb := new(strings.Builder)
		err = tmpl.Execute(sb, opt)
		if err != nil {
			return fmt.Errorf("unable to execute template: %w", err)
		}

		file := fmt.Sprintf("%s/auto.yaml", d)

		err = os.WriteFile(file, []byte(sb.String()), 0600)
		if err != nil {
			return fmt.Errorf("unable to create auto.yaml file: %w", err)
		}

		logger.WithField("autorun", sb.String()).Info("cmd config")

		port, err := portPool.getPort()
		if err != nil {
			return fmt.Errorf("too many requests: %w", err)
		}
		defer portPool.releasePort(port)

		out, outErr, exitCode, err := command.ExecuteWithEnvStdErr(ctx, logger,
			[]string{
				fmt.Sprintf("URL=%s", target),
				fmt.Sprintf("ZAPDIR=%s", d),
			},
			"/zap/zap.sh",
			"-dir", d,
			"-cmd", "-autorun", file,
			"-config", "database.recoverylog=false", // Reduce disk usage
			"-config", "network.connection.defaultUserAgent='Vulcan - Security Scanner - vulcan@adevinta.com'",
			"-port", strconv.Itoa(port),
			"-notel",  // Disables telemetry
			"-silent", // Prevents from checking for addon updates
		)
		if err != nil {
			logger.Errorf("Output of the ZAP daemon: %s", string(out))
			return fmt.Errorf("running zap: %w", err)
		}

		// Exit codes:
		// 0: Success
		// 1: At least 1 FAIL
		// 2: At least one WARN and no FAILs
		// 3: Any other failure
		if exitCode != 0 {
			logger.WithField("exitCode", exitCode).WithField("stdOut", string(out)).WithField("stdErr", string(outErr)).Info("Zap finished")
		}

		res, err := os.ReadFile(fmt.Sprintf("%s/report.json", d))
		if err != nil {
			return fmt.Errorf("unable to read report.json: %v", err)
		}

		r := Report{}
		if err = json.Unmarshal(res, &r); err != nil {
			return fmt.Errorf("unable to parse report: %v", err)
		}

		vulnerabilities := make(map[string]*report.Vulnerability)
		vulnSummary2PluginID := make(map[string]string)
		for _, site := range r.Site {
			logger.WithFields(logrus.Fields{
				"site.host":       site.Host,
				"site.num_alerts": len(site.Alerts)}).Info("alerts")
			if !strings.Contains(target, site.Host) {
				// This can happen i.e. when the openapi target url is other than the target.
				// DOUBT: Filter? exclude?
				logger.Warnf("Reporting alerts from an outside target %s %s", target, site.Host)
			}
			for _, a := range site.Alerts {

				cwe := 0
				if a.Cweid != "-1" {
					cwe, err = strconv.Atoi(a.Cweid)
					if err != nil {
						logger.Warnf("Wrong number Cweid %d", cwe)
					}
				}
				v := report.Vulnerability{
					Summary:         a.Name,
					Description:     trimP(a.Desc),
					Details:         a.Otherinfo,
					Recommendations: splitP(a.Solution),
					References:      splitP(a.Reference),
					Labels:          []string{"issue", "web", "zap", a.Pluginid}, // DOUBT: Added Pluginid as label.
					CWEID:           uint32(cwe),
					Score: func(risk string) float32 {
						switch risk {
						case "0":
							return report.SeverityThresholdNone
						case "1":
							return report.SeverityThresholdLow
						case "2":
							return report.SeverityThresholdMedium
						case "3":
							return report.SeverityThresholdHigh
						}
						return float32(report.SeverityNone)
					}(a.Riskcode),
				}

				// DOUBT: Only the fist instance?
				if len(a.Instances) > 0 {
					i := a.Instances[0]
					v.Resources = []report.ResourcesGroup{
						{
							Name: "Affected Requests",
							Header: []string{
								"Method",
								"URL",
								"Parameter",
								"Attack",
								"Evidence",
							},
							Rows: []map[string]string{
								{
									"Method":    i.Method,
									"URL":       i.URI,
									"Parameter": i.Param,
									"Attack":    i.Attack,
									"Evidence":  i.Evidence,
								},
							},
						},
					}
				}
				vulnSummary2PluginID[v.Summary] = a.Pluginid
				if _, ok := vulnerabilities[v.Summary]; ok {
					vulnerabilities[v.Summary].Resources[0].Rows = append(
						vulnerabilities[v.Summary].Resources[0].Rows,
						v.Resources[0].Rows...,
					)
				} else {
					vulnerabilities[v.Summary] = &v
				}
			}
		}
		for _, v := range vulnerabilities {
			// NOTE: Due to a signifcant number of false positive findings
			// reported for low severity issues by ZAP, the MinScore option
			// allows the check to skip reporting vulnerabilities with
			// score below a minimum threshold.
			if opt.MinScore > 0 && v.Score < opt.MinScore {
				logger.Debugf("Skipping vulnerability with low score: %+v", v)
				continue
			}

			resourcesFingerprint := ""
			pluginID := vulnSummary2PluginID[v.Summary]
			if len(v.Resources) > 0 && !isPluginIgnoredForFingerprint(opt, pluginID) {
				resourcesFingerprint = fingerprintFromResources(v.Resources[0].Rows)
			}
			v.Fingerprint = helpers.ComputeFingerprint(v.Score, resourcesFingerprint)

			state.AddVulnerabilities(*v)
		}

		return nil
	}

	c := check.NewCheckFromHandler(checkName, run)
	c.RunAndServe()
}

func trimP(html string) string {
	return strings.TrimSuffix(strings.TrimPrefix(html, "<p>"), "</p>")
}

func splitP(html string) []string {
	return strings.Split(trimP(html), "</p><p>")
}

func fingerprintFromResources(resources []map[string]string) string {
	var empty struct{}
	occurrences := []string{}
	occurrencesMap := make(map[string]struct{})
	// AffectedResource report data:
	//   {"Attack":"", "Evidence":"", "Method":"", "Parameter":"", "URL":""}
	// In order to compute the fingerprint we are gathering all elements from
	// the resources table except the URL because due to the nature of the
	// crawling/spider process results are not deterministic.
	for _, r := range resources {
		var a, e, m, p string
		if v, ok := r["Attack"]; ok {
			a = strings.ToLower(strings.TrimSpace(v))
		}
		if v, ok := r["Evidence"]; ok {
			e = strings.ToLower(strings.TrimSpace(v))
		}
		if v, ok := r["Method"]; ok {
			m = strings.ToLower(strings.TrimSpace(v))
		}
		if v, ok := r["Parameter"]; ok {
			p = strings.ToLower(strings.TrimSpace(v))
		}
		occurrenceKey := fmt.Sprintf("%s|%s|%s|%s", a, e, m, p)
		if _, ok := occurrencesMap[occurrenceKey]; !ok {
			occurrencesMap[occurrenceKey] = empty
			occurrences = append(occurrences, occurrenceKey)
		}
	}
	sort.Strings(occurrences)
	return strings.Join(occurrences, "#")
}

func isPluginIgnoredForFingerprint(opt options, pluginID string) bool {
	for _, ignoredID := range opt.IgnoredFingerprintScanners {
		if pluginID == ignoredID {
			return true
		}
	}
	return false
}

func createPortPool(first, count int) *pool {
	pp := pool{
		l: make([]int, count),
		m: sync.Mutex{},
	}
	for i := range pp.l {
		pp.l[i] = first + i
	}
	return &pp
}

func (p *pool) getPort() (int, error) {
	p.m.Lock()
	defer p.m.Unlock()
	if len(p.l) == 0 {
		return 0, fmt.Errorf("no ports available")
	}
	port := p.l[len(p.l)-1]
	p.l = p.l[:len(p.l)-1]
	return port, nil
}

func (p *pool) releasePort(port int) {
	p.m.Lock()
	defer p.m.Unlock()
	p.l = append(p.l, port)
}
