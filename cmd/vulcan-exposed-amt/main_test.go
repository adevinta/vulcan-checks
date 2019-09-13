package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	check "github.com/adevinta/vulcan-check-sdk"
	"github.com/adevinta/vulcan-check-sdk/agent"
	"github.com/adevinta/vulcan-check-sdk/config"
	"github.com/adevinta/vulcan-check-sdk/tools"
	report "github.com/adevinta/vulcan-report"
)

type buildTestServer func() *httptest.Server

type isAmtServerExposedTestArgs struct {
	target string
	port   string
}
type isAmtServerExposedTest struct {
	name              string
	args              isAmtServerExposedTestArgs
	testServerBuilder buildTestServer
	want              bool
	wantErr           bool
}

func buildExposedAMTTestServer() *httptest.Server {
	r := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/"+amtServerPath {
			w.Header().Set("server", amtServerHeaderToken)
			w.WriteHeader(http.StatusForbidden)
		}
	}))
	return r
}
func buildNotExposedAMTTestServer() *httptest.Server {
	r := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	return r
}

var isAmtExposedTestCases = []isAmtServerExposedTest{
	{
		name:              "HappyPathExposed",
		testServerBuilder: buildExposedAMTTestServer,
		// If a server is specified, there is no need to define args because are inferred from the server url.
		want: true,
	},
	{
		name:              "HappyPathNotExposed",
		testServerBuilder: buildNotExposedAMTTestServer,
		// If a server is specified, there is no need to define args because are inferred from the server url.
		want: false,
	},
	{
		name: "ErrorHostFormat",
		args: isAmtServerExposedTestArgs{
			port:   "error",
			target: "ds",
		},
		wantErr: true,
		// If a server is specified, there is no need to define args because are inferred from the server url.
		want: false,
	},
	{
		name: "ErrorNotReachable",
		args: isAmtServerExposedTestArgs{
			port:   "3005",
			target: "127.0.0.1",
		},
		wantErr: false,
		// If a server is specified, there is no need to define args because are inferred from the server url.
		want: false,
	},
}

func TestIsAmtServerExposed(t *testing.T) {

	for _, tt := range isAmtExposedTestCases {
		t.Run(tt.name, func(t *testing.T) {
			// if a test server builder function is defined call it and set test params according.
			if tt.testServerBuilder != nil {
				srv := tt.testServerBuilder()
				defer srv.Close()
				srvURL, err := url.Parse(srv.URL)
				if err != nil {
					t.Fatal(err)
				}
				host, port, err := net.SplitHostPort(srvURL.Host)
				if err != nil {
					t.Fatal(err)
				}
				tt.args.port = port
				tt.args.target = host
			}
			client := http.Client{
				Timeout: timeout * time.Second,
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse
				},
			}
			got, err := isAmtServerExposed(client, tt.args.target, tt.args.port)

			if err != nil && !tt.wantErr {
				t.Fatal(err)
			} else {
				if got != tt.want {
					t.Errorf("got %v, want %v", got, tt.want)
				}
			}
		})
	}
}

type runTest struct {
	name              string
	testServerBuilder buildTestServer
	target            string
	wantErr           bool
	score             float32
}

var runTestCases = []runTest{
	{
		name:              "HappyPath",
		testServerBuilder: buildExposedAMTTestServer,
		score:             9.8,
	},
}

func TestRun(t *testing.T) {
	for _, tt := range runTestCases {
		t.Run(tt.name, func(t *testing.T) {
			// if a test server builder function is defined call it and set test params according.
			if tt.testServerBuilder != nil {
				srv := tt.testServerBuilder()
				defer srv.Close()
				srvURL, err := url.Parse(srv.URL)
				if err != nil {
					t.Fatal(err)
				}
				host, port, err := net.SplitHostPort(srvURL.Host)
				if err != nil {
					t.Fatal(err)
				}
				// WARNING: Never run this tests in parallel.
				amtTCPPorts = []string{port}
				tt.target = host
			}
			a := tools.NewReporter("ID")
			b := true
			conf := &config.Config{
				Check: config.CheckConfig{
					CheckID:       "ID",
					Target:        tt.target,
					CheckTypeName: "vulcan-exposed-amt",
				},
				Log: config.LogConfig{
					LogFmt:   "text",
					LogLevel: "debug",
				},
				CommMode:        "push",
				AllowPrivateIPs: &b,
			}
			conf.Push.AgentAddr = a.URL
			conf.Push.BufferLen = 10
			c := check.NewCheckFromHandlerWithConfig("vulcan-exposed-amt", conf, run)
			// WARNING: Always stop the reporter after check finishes, if not, very nasty things can happen.
			c.RunAndServe()
			a.Stop()
			var msg agent.State
			for msg = range a.Msgs {
				if msg.Status == agent.StatusFailed || msg.Status == agent.StatusFinished {
					break
				}
			}

			if msg.Status == agent.StatusFailed && !tt.wantErr {
				t.Fatalf("check failed unexpectedly")
			}

			if report.AggregateScore(msg.Report.Vulnerabilities) != tt.score {
				t.Fatalf("check returned wrong score: got %v, wanted %v", report.AggregateScore(msg.Report.Vulnerabilities), tt.score)
			}

		})
	}
}
