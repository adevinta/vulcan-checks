/*
Copyright 2019 Adevinta
*/

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	check "github.com/adevinta/vulcan-check-sdk"
	"github.com/adevinta/vulcan-check-sdk/helpers"
	checkstate "github.com/adevinta/vulcan-check-sdk/state"
	report "github.com/adevinta/vulcan-report"
	"github.com/sirupsen/logrus"
	"github.com/zaproxy/zap-api-go/zap"
)

var (
	checkName = "vulcan-zap"
	logger    = check.NewCheckLog(checkName)
	client    zap.Interface
)

const contextName = "target"

type options struct {
	Depth    int     `json:"depth"`
	Active   bool    `json:"active"`
	Port     int     `json:"port"`
	Username string  `json:"username"`
	Password string  `json:"password"`
	MinScore float32 `json:"min_score"`
	// List of active/passive scanners to disable by their identifiers:
	// https://www.zaproxy.org/docs/alerts/
	DisabledScanners           []string `json:"disabled_scanners"`
	IgnoredFingerprintScanners []string `json:"ignored_fingerprint_scanners"`
	MaxSpiderDuration          int      `json:"max_spider_duration"`
	MaxScanDuration            int      `json:"max_scan_duration"`
	MaxRuleDuration            int      `json:"max_rule_duration"`
	MaxAlertsPerRule           int      `json:"max_alerts_per_rule"`
	OpenapiUrl                 string   `json:"openapi_url"`
	OpenapiHost                string   `json:"openapi_host"`
}

func main() {
	run := func(_ context.Context, target, assetType, optJSON string, state checkstate.State) (err error) {
		var opt options
		if optJSON != "" {
			if err = json.Unmarshal([]byte(optJSON), &opt); err != nil {
				return err
			}
		}

		disabledScanners := strings.Join(opt.DisabledScanners, ",")

		isReachable, err := helpers.IsReachable(target, assetType, nil)
		if err != nil {
			logger.Warnf("Can not check asset reachability: %v", err)
		}
		if !isReachable {
			return checkstate.ErrAssetUnreachable
		}

		ctx, ctxCancel := context.WithCancel(context.Background())

		// Execute ZAP daemon.
		go func() {
			logger.Print("Executing for ZAP daemon...")
			out, err := exec.Command(
				"/zap/zap.sh",
				"-daemon", "-host", "127.0.0.1", "-port", "8080",
				"-config", "api.disablekey=true",
				"-config", "database.recoverylog=false", // Reduce disk usage
				"-notel",  // Disables telemetry
				"-silent", // Prevents from checking for addon updates
			).Output()

			logger.Debugf("Error executing ZAP daemon: %v", err)
			logger.Debugf("Output of the ZAP daemon: %s", string(out))

			ctxCancel()
		}()

		// Wait for ZAP to be available.
		logger.Print("Waiting for ZAP proxy...")
		ticker := time.NewTicker(time.Second)
	proxyLoop:
		for {
			select {
			case <-ctx.Done():
				return errors.New("ZAP exited while waiting for proxy")
			case <-ticker.C:
				conn, _ := net.DialTimeout("tcp", "127.0.0.1:8080", time.Second)
				if conn != nil {
					conn.Close()
					break proxyLoop
				}
			}
		}

		logger.Print("Initiating ZAP client...")

		cfg := &zap.Config{
			Proxy:     "http://127.0.0.1:8080",
			Base:      "http://127.0.0.1:8080/JSON/",
			BaseOther: "http://127.0.0.1:8080/OTHER/",
		}
		client, err = zap.NewClient(cfg)
		if err != nil {
			return fmt.Errorf("error configuring the ZAP proxy client: %w", err)
		}

		client.Core().SetOptionDefaultUserAgent("Vulcan - Security Scanner - vulcan@adevinta.com")

		targetURL, err := url.Parse(target)
		if err != nil {
			return fmt.Errorf("error parsing target URL: %w", err)
		}

		cx, err := client.Context().NewContext(contextName)
		if err != nil {
			return fmt.Errorf("error creating scope context: %w", err)
		}
		contextID, err := getStringAttribute(cx, "contextId")
		if err != nil {
			return err
		}

		// Add base URL to the scope.
		targetPort := ""
		if targetURL.Port() != "" {
			targetPort = fmt.Sprintf(":%s", targetURL.Port())
		}
		hostnameRegExQuote := strings.Replace(targetURL.Hostname(), `.`, `\.`, -1)
		includeInContextRegEx := fmt.Sprintf(`http(s)?:\/\/%s%s\/.*`, hostnameRegExQuote, targetPort)
		logger.Printf("include in context regexp: %s", includeInContextRegEx)
		_, err = client.Context().IncludeInContext(contextName, includeInContextRegEx)
		if err != nil {
			return fmt.Errorf("error including target URL to context: %w", err)
		}

		_, err = client.Context().SetContextInScope(contextName, "True")
		if err != nil {
			return fmt.Errorf("error setting context in scope: %w", err)
		}

		if opt.Username != "" {
			auth := client.Authentication()
			auth.SetAuthenticationMethod("1", "httpAuthentication", fmt.Sprintf("hostname=%v&port=%v", targetURL.Hostname(), targetURL.Port()))

			users := client.Users()
			users.NewUser("1", opt.Username)
			users.SetAuthenticationCredentials("1", "0", fmt.Sprintf("username=%v&password=%v", opt.Username, opt.Password))
			users.SetUserEnabled("1", "0", "True")
		}

		if opt.OpenapiUrl != "" {
			_, err = client.Openapi().ImportUrl(opt.OpenapiUrl, opt.OpenapiHost, contextID)
			if err != nil {
				return fmt.Errorf("error importing openapi url: %w", err)
			}
		}

		_, err = client.Pscan().DisableScanners(disabledScanners)
		if err != nil {
			return fmt.Errorf("error disabling scanners for passive scan: %w", err)
		}

		_, err = client.Spider().SetOptionMaxDepth(opt.Depth)
		if err != nil {
			return fmt.Errorf("error setting spider max depth: %w", err)
		}
		_, err = client.Spider().SetOptionMaxDuration(opt.MaxSpiderDuration)
		if err != nil {
			return fmt.Errorf("error setting spider max duration: %w", err)
		}

		// Apply zap_tune optimizations.
		_, err = client.Pscan().SetMaxAlertsPerRule(strconv.Itoa(opt.MaxAlertsPerRule))
		if err != nil {
			return fmt.Errorf("error setting max alerts per rule: %w", err)
		}
		_, err = client.Pscan().DisableAllTags()
		if err != nil {
			return fmt.Errorf("error disabling all tags: %w", err)
		}

		logger.Printf("Running spider %v levels deep, max duration %v, ...", opt.Depth, opt.MaxSpiderDuration)

		resp, err := client.Spider().Scan(targetURL.String(), "", contextName, "", "")
		if err != nil {
			return fmt.Errorf("error executing the spider: %w", err)
		}

		v, ok := resp["scan"]
		if !ok {
			// Scan has not been executed. Due to the ZAP proxy behaviour
			// (the request to the ZAP API does not return the status codes)
			// we can not be sure whether it was because a non existant target
			// or because an error accessing the ZAP API. Therefore, we will
			// terminate the check without errors.
			logger.WithFields(logrus.Fields{"resp": resp}).Warn("Scan not present in response body when calling Spider().Scan()")
			return nil
		}

		scanid, ok := v.(string)
		if !ok {
			return errors.New("scan is present in response body when calling Spider().Scan() but it is not a string")
		}

		ticker = time.NewTicker(10 * time.Second)
	spiderLoop:
		for {
			select {
			case <-ctx.Done():
				return errors.New("ZAP exited while waiting for spider")
			case <-ticker.C:
				resp, err := client.Spider().Status(scanid)
				if err != nil {
					return fmt.Errorf("error getting the status of the spider: %w", err)
				}
				v, ok := resp["status"]
				if !ok {
					// In this case if we can not get the status let's fail.
					return fmt.Errorf("can not retrieve the status of the spider %v", resp)
				}
				status, ok := v.(string)
				if !ok {
					return errors.New("status is present in response body when calling Spider().Scatus() but it is not a string")
				}

				progress, err := strconv.Atoi(status)
				if err != nil {
					return fmt.Errorf("can not convert status value %s into an int", status)
				}

				logger.Debugf("Spider at %v progress.", progress)

				if opt.Active {
					state.SetProgress(float32(progress) / 200)
				} else {
					state.SetProgress(float32(progress) / 100)
				}

				if progress >= 100 {
					break spiderLoop
				}
			}
		}

		logger.Print("Waiting for spider results...")
		time.Sleep(5 * time.Second)

		resp, err = client.Spider().AllUrls()
		if err != nil {
			return fmt.Errorf("error getting the list of URLs from spider: %w", err)
		}
		logger.Printf("Spider found the following URLs: %+v", resp)

		_, err = client.AjaxSpider().SetOptionMaxDuration(opt.MaxSpiderDuration)
		if err != nil {
			return fmt.Errorf("error setting ajax spider max duration: %w", err)
		}

		logger.Printf("Running AJAX spider %v levels deep, max duration %v...", opt.Depth, opt.MaxSpiderDuration)

		client.AjaxSpider().SetOptionMaxCrawlDepth(opt.Depth)
		_, err = client.AjaxSpider().Scan(targetURL.String(), "", contextName, "")
		if err != nil {
			return fmt.Errorf("error executing the AJAX spider: %w", err)
		}

		ticker = time.NewTicker(10 * time.Second)
	ajaxSpiderLoop:
		for {
			select {
			case <-ctx.Done():
				return errors.New("ZAP exited while waiting for AJAX spider")
			case <-ticker.C:
				resp, err := client.AjaxSpider().Status()
				if err != nil {
					return fmt.Errorf("error getting the status of the AJAX spider: %w", err)
				}

				v, ok := resp["status"]
				if !ok {
					// In this case if we can not get the status let's fail.
					return errors.New("can not retrieve the status of the AJAX spider")
				}
				status, ok := v.(string)
				if !ok {
					return errors.New("status is present in response body when calling AjaxSpider().Scatus() but it is not a string")
				}

				if status >= "running" {
					break ajaxSpiderLoop
				}
			}
		}

		logger.Print("Waiting for AJAX spider results...")
		time.Sleep(5 * time.Second)

		resp, err = client.AjaxSpider().FullResults()
		if err != nil {
			return fmt.Errorf("error getting the list of URLs from AJAX spider: %w", err)
		}
		logger.Printf("AJAX spider found the following URLs: %+v", resp)

		// Scan actively only if explicitly indicated.
		if opt.Active {
			logger.Print("Running active scan...")
			err := activeScan(ctx, targetURL, state, disabledScanners, opt.MaxScanDuration, opt.MaxRuleDuration, contextID)
			if err != nil {
				return err
			}
			logger.Print("Waiting for active scan results...")
			time.Sleep(5 * time.Second)
		}

		// Retrieve alerts.
		alerts, err := client.Core().Alerts("", "", "", "")
		if err != nil {
			return fmt.Errorf("error retrieving alerts: %v", alerts)
		}

		alertsSlice, ok := alerts["alerts"].([]interface{})
		if !ok {
			return errors.New("alerts does not exist or it is not an array of interface{}")
		}

		vulnerabilities := make(map[string]*report.Vulnerability)
		vulnSummary2PluginID := make(map[string]string)
		for _, alert := range alertsSlice {
			a, ok := alert.(map[string]interface{})
			if !ok {
				return errors.New("alert it is not a map[string]interface{}")
			}

			v, err := processAlert(a)
			if err != nil {
				logger.WithError(err).Warn("can not process alert")
				continue
			}
			pluginID, err := parsePluginID(a)
			if err != nil {
				logger.WithError(err).Warn("can not parse plugin ID")
				continue
			}
			vulnSummary2PluginID[v.Summary] = pluginID

			if _, ok := vulnerabilities[v.Summary]; ok {
				vulnerabilities[v.Summary].Resources[0].Rows = append(
					vulnerabilities[v.Summary].Resources[0].Rows,
					v.Resources[0].Rows...,
				)
			} else {
				vulnerabilities[v.Summary] = &v
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

func activeScan(ctx context.Context, targetURL *url.URL, state checkstate.State, disabledScanners string, maxScanDuration, maxRuleDuration int, contextID string) error {
	_, err := client.Ascan().DisableScanners(disabledScanners, "")
	if err != nil {
		return fmt.Errorf("error disabling scanners for active scan: %w", err)
	}

	_, err = client.Ascan().SetOptionMaxScanDurationInMins(maxScanDuration)
	if err != nil {
		return fmt.Errorf("error setting max scan duration for active scan: %w", err)
	}

	_, err = client.Ascan().SetOptionMaxRuleDurationInMins(maxRuleDuration)
	if err != nil {
		return fmt.Errorf("error setting max rule duration for active scan: %w", err)
	}

	resp, err := client.Ascan().Scan("", "True", "", "", "", "", contextID)
	if err != nil {
		return fmt.Errorf("error executing the active scan: %w", err)
	}

	v, ok := resp["scan"]
	if !ok {
		return fmt.Errorf("scan is not present in response body when calling Ascan().Scan()")
	}

	scanid, ok := v.(string)
	if !ok {
		return errors.New("scan is present in response body when calling Ascan().Scan() but it is not a string")
	}

	ticker := time.NewTicker(60 * time.Second)
	for {
		select {
		case <-ctx.Done():
			return errors.New("ZAP exited while waiting for active scan")
		case <-ticker.C:
			ascan := client.Ascan()

			resp, err := ascan.Status(scanid)
			if err != nil {
				return fmt.Errorf("error getting the status of the scan: %w", err)
			}

			v, ok := resp["status"]
			if !ok {
				// In this case if we can not get the status let's fail.
				return errors.New("can not retrieve the status of the scan")
			}
			status, ok := v.(string)
			if !ok {
				return errors.New("status is present in response body when calling Ascan().Scatus() but it is not a string")
			}
			progress, err := strconv.Atoi(status)
			if err != nil {
				return fmt.Errorf("can not convert status value %s into an int", status)
			}

			state.SetProgress((1 + float32(progress)) / 200)

			logger.Debugf("Active scan at %v progress.", progress)
			if progress >= 100 {
				return nil
			}
		}
	}
}

func isPluginIgnoredForFingerprint(opt options, pluginID string) bool {
	for _, ignoredID := range opt.IgnoredFingerprintScanners {
		if pluginID == ignoredID {
			return true
		}
	}
	return false
}

func getStringAttribute(m map[string]any, name string) (string, error) {
	v, ok := m[name]
	if !ok {
		return "", fmt.Errorf("error %s not found", name)
	}
	str, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("error %s value [%v] is not a string", name, v)
	}
	return str, nil
}
