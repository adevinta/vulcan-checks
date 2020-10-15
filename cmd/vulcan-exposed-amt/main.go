package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/sirupsen/logrus"

	check "github.com/adevinta/vulcan-check-sdk"
	"github.com/adevinta/vulcan-check-sdk/state"
	report "github.com/adevinta/vulcan-report"
)

const timeout = 2

var (
	checkName            = "vulcan-exposed-amt"
	amtTCPPorts          = []string{"623", "664", "16992", "16993", "16994", "16995"}
	amtServerPath        = "index.htm"
	amtServerHeaderToken = "Intel(R) Active Management Technology"
	// CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
	// https://nvd.nist.gov/vuln/detail/CVE-2017-5689
	exposedAMTPort = report.Vulnerability{
		Summary:       "Exposed Intel AMT Ports",
		Description:   "The port is comonly used by Intel AMT, which allows remote computer management from the network.",
		Score:         9.8,
		ImpactDetails: "If Intel AMT is enabled and exposed to a network, an attacker from that network can exploit it to gain complete access to a vulnerable machine. In some cases, an attacker might be able to gain access without a vulnerability being present by bruteforcing administrative credentials or using default ones.",
		References: []string{
			"https://www.ssh.com/vulnerability/intel-amt/",
			"https://nvd.nist.gov/vuln/detail/CVE-2017-5689"},
		Recommendations: []string{"Block access to Intel AMT ports from the internet.", "Disable Intel AMT if not in use."},
	}
)

type options struct {
	Timeout int `json:"timeout"`
}

func isAmtServerExposed(client http.Client, target, port string) (bool, error) {
	var exposed bool
	host := fmt.Sprintf("%s:%s", target, port)
	address := url.URL{
		Host:   host,
		Path:   amtServerPath,
		Scheme: "http",
	}
	r, err := http.NewRequest("GET", address.String(), nil)
	if err != nil {
		// An error here should always mean an error in code.
		return false, err
	}
	resp, err := client.Do(r)
	if err != nil {
		err = fmt.Errorf("%w: %s", state.ErrAssetUnreachable, err.Error())
		return false, err
	}

	// Check server header in response for amt server token.
	srvHeader := resp.Header.Get("server")
	if srvHeader == amtServerHeaderToken {
		exposed = true
	}
	return exposed, nil
}

func run(ctx context.Context, target string, optJSON string, state state.State) (err error) {
	logger := check.NewCheckLog(checkName)

	var opt options
	if optJSON != "" {
		if err = json.Unmarshal([]byte(optJSON), &opt); err != nil {
			return err
		}
	} else {
		opt.Timeout = timeout
	}

	client := http.Client{
		Timeout: time.Duration(opt.Timeout) * time.Second,
		// Don't follow redirects
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	gr := report.ResourcesGroup{
		Name: "Network Resources",
		Header: []string{
			"Hostname",
			"Port",
			"Protocol",
			"Service",
		},
	}
	add := false
	for _, port := range amtTCPPorts {
		open, err := isAmtServerExposed(client, target, port)
		if err != nil {
			return err
		}
		if open {
			add = true

			networkResource := map[string]string{
				"Hostname": target,
				"Port":     port,
				"Protocol": "tcp",
				"Service":  amtServerHeaderToken,
			}
			gr.Rows = append(gr.Rows, networkResource)

			logger.WithFields(logrus.Fields{"port": port}).Debug("Found open port.")
		}
	}
	if add {
		exposedAMTPort.Resources = append(exposedAMTPort.Resources, gr)
		state.AddVulnerabilities(exposedAMTPort)
	}

	return nil
}

func main() {

	c := check.NewCheckFromHandler(checkName, run)
	c.RunAndServe()
}
