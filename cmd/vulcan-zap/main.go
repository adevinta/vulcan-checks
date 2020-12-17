package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os/exec"
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
	err       error
)

type options struct {
	Depth    int     `json:"depth"`
	Active   bool    `json:"active"`
	Port     int     `json:"port"`
	Username string  `json:"username"`
	Password string  `json:"password"`
	MinScore float32 `json:"min_score"`
	// List of active/passive scanners to disable by their identifiers:
	// https://www.zaproxy.org/docs/alerts/
	DisabledScanners []string `json:"disabled_scanners"`
}

func main() {
	run := func(ctx context.Context, target, assetType, optJSON string, state checkstate.State) (err error) {
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

		if opt.Username != "" {
			auth := client.Authentication()
			auth.SetAuthenticationMethod("1", "httpAuthentication", fmt.Sprintf("hostname=%v&port=%v", targetURL.Hostname(), targetURL.Port()))

			users := client.Users()
			users.NewUser("1", opt.Username)
			users.SetAuthenticationCredentials("1", "0", fmt.Sprintf("username=%v&password=%v", opt.Username, opt.Password))
			users.SetUserEnabled("1", "0", "True")
		}

		_, err = client.Pscan().DisableScanners(disabledScanners)
		if err != nil {
			return fmt.Errorf("error disabling scanners for passive scan: %w", err)
		}

		logger.Printf("Running spider %v levels deep...", opt.Depth)

		client.Spider().SetOptionMaxDepth(opt.Depth)
		resp, err := client.Spider().Scan(targetURL.String(), "", "", "", "")
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
					return errors.New("can not retrieve the status of the spider")
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

		logger.Printf("Running AJAX spider %v levels deep...", opt.Depth)

		client.AjaxSpider().SetOptionMaxCrawlDepth(opt.Depth)
		resp, err = client.AjaxSpider().Scan(targetURL.String(), "", "", "")
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

		// Scan actively only if explicitly indicated.
		if opt.Active {
			logger.Print("Running active scan...")
			err := activeScan(ctx, targetURL, state, disabledScanners)
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

			state.AddVulnerabilities(*v)
		}

		return nil
	}

	c := check.NewCheckFromHandler(checkName, run)
	c.RunAndServe()
}

func activeScan(ctx context.Context, targetURL *url.URL, state checkstate.State, disabledScanners string) error {
	_, err := client.Ascan().DisableScanners(disabledScanners, "")
	if err != nil {
		return fmt.Errorf("error disabling scanners for active scan: %w", err)
	}

	resp, err := client.Ascan().Scan(targetURL.String(), "True", "False", "", "", "", "")
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
