package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os/exec"
	"strconv"
	"time"

	"github.com/adevinta/vulcan-check-sdk"
	"github.com/adevinta/vulcan-check-sdk/state"
	report "github.com/adevinta/vulcan-report"
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
			log.Println("Executing for ZAP daemon...")
			out, err := exec.Command(
				"/zap/zap.sh",
				"-daemon", "-host", "127.0.0.1", "-port", "8080",
				"-config", "api.disablekey=true",
			).Output()
			log.Printf("Error executing ZAP daemon: %v", err)
			log.Printf("Output of the ZAP daemon: %s", out)
		}()

		// Wait for ZAP to be available.
		for {
			log.Println("Waiting for ZAP proxy...")
			time.Sleep(time.Second)
			conn, _ := net.DialTimeout("tcp", "127.0.0.1:8080", time.Second)
			if conn != nil {
				conn.Close()
				break
			}
		}

		log.Println("Initiating ZAP client...")

		cfg := &zap.Config{
			Proxy:     "http://127.0.0.1:8080",
			Base:      "http://127.0.0.1:8080/JSON/",
			BaseOther: "http://127.0.0.1:8080/OTHER/",
		}
		client, err := zap.NewClient(cfg)
		if err != nil {
			return err
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

		log.Printf("Running spider %v levels deep...", opt.Depth)

		client.Spider().SetOptionMaxDepth(opt.Depth)
		resp, err := client.Spider().Scan(targetURL.String(), "", "", "", "")
		if err != nil {
			return err
		}

		scanid := resp["scan"].(string)
		for {
			time.Sleep(1 * time.Second)
			resp, _ = client.Spider().Status(scanid)

			progress, _ := strconv.Atoi(resp["status"].(string))
			log.Printf("Spider at %v progress.", progress)

			if opt.Active {
				state.SetProgress(float32(progress) / 200)
			} else {
				state.SetProgress(float32(progress) / 100)
			}

			if progress >= 100 {
				break
			}
		}

		log.Println("Waiting for spider results...")
		time.Sleep(5 * time.Second)

		// Scan actively only if explicitly indicated.
		if opt.Active {
			log.Println("Running active scan...")

			resp, err = client.Ascan().Scan(targetURL.String(), "True", "False", "", "", "", "")
			if err != nil {
				return err
			}

			scanid = resp["scan"].(string)
			for {
				time.Sleep(5 * time.Second)
				ascan := client.Ascan()
				resp, _ = ascan.Status(scanid)

				progress, _ := strconv.Atoi(resp["status"].(string))
				state.SetProgress((1 + float32(progress)) / 200)
				log.Printf("Active scan at %v progress.", progress)
				if progress >= 100 {
					break
				}
			}

			log.Println("Waiting for active scan results...")
			time.Sleep(5 * time.Second)
		}

		// Retrieve alerts.
		alerts, err := client.Core().Alerts("", "", "", "")
		if err != nil {
			return err
		}

		alertsSlice := alerts["alerts"].([]interface{})

		vulnerabilities := make(map[string]*report.Vulnerability)
		for _, alert := range alertsSlice {
			a := alert.(map[string]interface{})

			v, err := processAlert(a)
			if err != nil {
				log.Println(err)
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
