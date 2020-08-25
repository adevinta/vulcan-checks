package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"

	check "github.com/adevinta/vulcan-check-sdk"
	"github.com/adevinta/vulcan-check-sdk/state"
	"github.com/adevinta/vulcan-checks/cmd/vulcan-burp/resturp"
)

const (
	activeScanMode  = "active"
	passiveScanMode = "passive"
	burpEndPointEnv = "BURP_API_ENDPOINT"
)

var (
	checkName = "vulcan-burp"

	logger = check.NewCheckLog(checkName)

	// ErrNoBurpAPIEndPoint is returned by the check when the burp api url is
	// not defined.
	ErrNoBurpAPIEndPoint = errors.New("BURP_API_ENDPOINT env var must be set")

	// ErrInvalidScanMode is returned when an invalid scan mode was specified.
	ErrInvalidScanMode = errors.New("invalid scan mode")
)

type options struct {
	ScanMode ScanMode `json:"scan_mode"`
}

// ScanMode possible scan modes are: "active" and "passive"
type ScanMode string

func (s ScanMode) toBurpConfigs() ([]string, error) {
	if s == "passive" || s == "" {
		return []string{"Crawl limit - 10 minutes", "Audit checks - passive"}, nil
	}

	if s == "active" {
		return []string{"Crawl limit - 10 minutes", "Audit coverage - maximum"}, nil
	}

	return nil, fmt.Errorf("%w, mode specified was %s, only valid modes are: active, passive", ErrInvalidScanMode, s)
}

func buildOptions(optJSON string) (options, error) {
	var opts options
	if optJSON != "" {
		if err := json.Unmarshal([]byte(optJSON), &opts); err != nil {
			return opts, err
		}
	}

	if opts.ScanMode == "" {
		opts.ScanMode = passiveScanMode
	}

	return opts, nil
}

func main() {
	c := check.NewCheckFromHandler(checkName, run)
	c.RunAndServe()
}

func run(ctx context.Context, target string, optJSON string, state state.State) error {
	if target == "" {
		return errors.New("check target missing")
	}
	api, ok := os.LookupEnv(burpEndPointEnv)
	if !ok {
		return ErrNoBurpAPIEndPoint
	}

	opts, err := buildOptions(optJSON)
	if err != nil {
		return err
	}
	configs, err := opts.ScanMode.toBurpConfigs()
	if err != nil {
		return err
	}
	c, err := resturp.New(http.DefaultClient, api, "")
	if err != nil {
		return err
	}

	id, err := c.LaunchScan(target, configs)
	if err != nil {
		return err
	}
	fmt.Printf("task id %d", id)
	return nil
}
