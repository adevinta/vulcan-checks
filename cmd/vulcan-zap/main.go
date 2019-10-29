package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"time"

	check "github.com/adevinta/vulcan-check-sdk"
	"github.com/adevinta/vulcan-check-sdk/state"
	report "github.com/adevinta/vulcan-report"
	"github.com/sirupsen/logrus"
	"github.com/zaproxy/zap-api-go/zap"
)

var (
	checkName = "vulcan-zap"
	logger    = check.NewCheckLog(checkName)
)

type options struct {
	Depth    int    `json:"depth"`
	Active   bool   `json:"active"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
}

func main() {
	run := func(ctx context.Context, target string, optJSON string, state state.State) (err error) {
		var opt options
		if optJSON != "" {
			if err = json.Unmarshal([]byte(optJSON), &opt); err != nil {
				return err
			}
		}

		// Execute ZAP daemon.
		go func() {
			logger.Debug("Executing for ZAP daemon...")
			out, err := exec.Command(
				"/zap/zap.sh",
				"-daemon", "-host", "127.0.0.1", "-port", "8080",
				"-config", "api.disablekey=true",
			).Output()
			logger.Debugf("Error executing ZAP daemon: %v", err)
			logger.Debugf("Output of the ZAP daemon: %s", out)
		}()

		// Wait for ZAP to be available.
		for {
			logger.Debug("Waiting for ZAP proxy...")
			time.Sleep(time.Second)
			conn, _ := net.DialTimeout("tcp", "127.0.0.1:8080", time.Second)
			if conn != nil {
				conn.Close()
				break
			}
		}

		logger.Debug("Initiating ZAP client...")

		cfg := &zap.Config{
			Proxy:     "http://127.0.0.1:8080",
			Base:      "http://127.0.0.1:8080/JSON/",
			BaseOther: "http://127.0.0.1:8080/OTHER/",
		}
		client, err := zap.NewClient(cfg)
		if err != nil {
			return fmt.Errorf("error configuring the zap proxy client: %v", err)
		}

		client.Core().SetOptionDefaultUserAgent("Vulcan - Security Scanner - vulcan@adevinta.com")

		targetURL := hostnameToURL(target, opt.Port)

		if opt.Username != "" {
			auth := client.Authentication()
			auth.SetAuthenticationMethod("1", "httpAuthentication", fmt.Sprintf("hostname=%v&port=%v", targetURL.Hostname(), targetURL.Port()))

			users := client.Users()
			users.NewUser("1", opt.Username)
			users.SetAuthenticationCredentials("1", "0", fmt.Sprintf("username=%v&password=%v", opt.Username, opt.Password))
			users.SetUserEnabled("1", "0", "True")
		}

		logger.Debugf("Running spider %v levels deep...", opt.Depth)

		client.Spider().SetOptionMaxDepth(opt.Depth)
		resp, err := client.Spider().Scan(targetURL.String(), "", "", "", "")
		if err != nil {
			return fmt.Errorf("error executing the spider: %v", err)
		}

		v, ok := resp["scan"]
		if !ok {
			// Scan has not been executed. Due to the ZAP proxy behaviour
			// (the request to the ZAP API does not return the status codes)
			// we can not be sure whether it was because a non existant target
			// or because an error accessing the ZAP API. Therefore, we will
			// terminate the check without errors.
			logger.WithFields(logrus.Fields{"resp": resp}).Error("Scan not present in response body when calling Spider().Scan()")
			return nil
		}

		scanid, ok := v.(string)
		if !ok {
			return errors.New("scan is present in response body when calling Spider().Scan() but it is not a string")
		}

		for {
			time.Sleep(1 * time.Second)
			resp, err := client.Spider().Status(scanid)
			if err != nil {
				return fmt.Errorf("error getting the status of the scan: %v", err)
			}

			v, ok := resp["status"]
			if !ok {
				// In this case if we can not get the status let's fail.
				return errors.New("can not retrieve the status of the scan")
			}
			status, ok := v.(string)
			if !ok {
				return errors.New("status is present in response body when calling Spider().Scatus() but it is not a string")
			}
			progress, err := strconv.Atoi(status)
			if err != nil {
				return fmt.Errorf("can not convert status value %s into an int", progress)
			}

			logger.Debugf("Spider at %v progress.", progress)

			if opt.Active {
				state.SetProgress(float32(progress) / 200)
			} else {
				state.SetProgress(float32(progress) / 100)
			}

			if progress >= 100 {
				break
			}
		}

		logger.Debug("Waiting for spider results...")
		time.Sleep(5 * time.Second)

		// Scan actively only if explicitly indicated.
		if opt.Active {
			logger.Debug("Running active scan...")

			resp, err = client.Ascan().Scan(targetURL.String(), "True", "False", "", "", "", "")
			if err != nil {
				return fmt.Errorf("error executing the active scan: %v", err)
			}

			v, ok := resp["scan"]
			if !ok {
				return fmt.Errorf("scan is not present in response body when calling Ascan().Scan()")
			}

			scanid, ok := v.(string)
			if !ok {
				return errors.New("scan is present in response body when calling Ascan().Scan() but it is not a string")
			}

			for {
				time.Sleep(5 * time.Second)

				ascan := client.Ascan()

				resp, err := ascan.Status(scanid)
				if err != nil {
					return fmt.Errorf("error getting the status of the scan: %v", err)
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
					return fmt.Errorf("can not convert status value %s into an int", progress)
				}

				state.SetProgress((1 + float32(progress)) / 200)

				logger.Debugf("Active scan at %v progress.", progress)
				if progress >= 100 {
					break
				}
			}

			logger.Debug("Waiting for active scan results...")
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
				logger.WithError(err).Error("can not process alert")
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
			state.AddVulnerabilities(*v)
		}

		return nil
	}

	c := check.NewCheckFromHandler(checkName, run)
	c.RunAndServe()
}
