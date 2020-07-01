package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"

	check "github.com/adevinta/vulcan-check-sdk"
	"github.com/adevinta/vulcan-check-sdk/state"
	report "github.com/adevinta/vulcan-report"
	"github.com/aws/aws-sdk-go/aws/arn"
)

const (
	defaultRegion          = `eu-west-1`
	defaultSessionDuration = 3600 // 1 hour.

	envEndpoint = `VULCAN_ASSUME_ROLE_ENDPOINT`
	envRole     = `ROLE_NAME`

	envKeyID     = `AWS_ACCESS_KEY_ID`
	envKeySecret = `AWS_SECRET_ACCESS_KEY`
	envToken     = `AWS_SESSION_TOKEN`
)

var (
	checkName = "vulcan-prowler"
	logger    = check.NewCheckLog(checkName)

	defaultGroups = []string{
		"cislevel2",
	}

	CISCompliance = report.Vulnerability{
		Summary: "Compliance With CIS AWS Foundations Benchmark (BETA)",
		Description: `<p>
			The CIS AWS Foundations Benchmark provides prescriptive
			guidance for configuring security options for a subset of Amazon Web
			Services with an emphasis on foundational, testable, and architecture
			agnostic settings. The services included in the scope are:
		</p>
		<p>
		<ul>
			<li>IAM</li>
			<li>Config</li>
			<li>CloudTrail</li>
			<li>CloudWatch</li>
			<li>SNS</li>
			<li>S3</li>
			<li>VPC (Default)</li>
		</ul>
		</p>
		<p>
			The provided recommendations are classified in 2 different levels: 1
			and 2, being the level 2 intended for environments or use cases where
			security is paramount.
		</p>
		<p>
			Check the Details and Resources sections to know the compliance status
			and more details.
		</p>`,
		References: []string{
			"https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf",
			"https://github.com/toniblyx/prowler",
			"https://www.cisecurity.org/benchmark/amazon_web_services/",
		},
	}
)

type options struct {
	Region          string   `json:"region"`
	Groups          []string `json:"groups"`
	SessionDuration int      `json:"sessionDuration"` // In secs.
}

func buildOptions(optJSON string) (options, error) {
	var opts options
	if optJSON != "" {
		if err := json.Unmarshal([]byte(optJSON), &opts); err != nil {
			return opts, err
		}
	}
	if opts.Region == "" {
		opts.Region = defaultRegion
	}
	if opts.Groups == nil {
		opts.Groups = defaultGroups
	}
	if opts.SessionDuration == 0 {
		opts.SessionDuration = defaultSessionDuration
	}

	return opts, nil
}

func main() {
	run := func(ctx context.Context, target string, optJSON string, state state.State) error {
		if target == "" {
			return errors.New("check target missing")
		}
		parsedARN, err := arn.Parse(target)
		if err != nil {
			return err
		}

		opts, err := buildOptions(optJSON)
		if err != nil {
			return err
		}

		endpoint := os.Getenv(envEndpoint)
		if endpoint == "" {
			return fmt.Errorf("%s env var must have a non-empty value", envEndpoint)
		}
		role := os.Getenv(envRole)

		logger.Infof("using endpoint '%s' and role '%s'", endpoint, role)

		if err := loadCredentials(endpoint, parsedARN.AccountID, role, opts.SessionDuration); err != nil {
			return fmt.Errorf("can not get credentials for the role '%s' from the endpoint '%s': %w", endpoint, role, err)
		}

		alias, err := accountAlias(credentials.NewEnvCredentials())
		if err != nil {
			return fmt.Errorf("can not retrieve account alias: %w", err)
		}

		logger.Infof("account alias: '%s'", alias)

		report, err := runProwler(ctx, opts)
		if err != nil {
			return err
		}

		addVulnsToState(state, report, alias)

		return nil

	}

	c := check.NewCheckFromHandler(checkName, run)
	c.RunAndServe()
}

func addVulnsToState(state state.State, r *prowlerReport, alias string) {
	v := CISCompliance

	fcTable := report.ResourcesGroup{
		Name: "Failed Controls",
		Header: []string{
			"Level",
			"Control",
			"Region",
			"Message",
		},
	}

	infoTable := report.ResourcesGroup{
		Name: "Additional Info",
		Header: []string{
			"Level",
			"Control",
			"Region",
			"Message",
		},
	}

	var passed []entry
	var failed []entry
	var info []entry
	for _, e := range r.entries {
		switch e.Status {
		case "Pass":
			passed = append(passed, e)
		case "Info":
			info = append(info, e)
			row := map[string]string{
				"Level":   e.Level,
				"Control": e.Control,
				"Region":  e.Region,
				"Message": e.Message,
			}
			infoTable.Rows = append(infoTable.Rows, row)
		case "FAIL":
			failed = append(failed, e)
			row := map[string]string{
				"Level":   e.Level,
				"Control": e.Control,
				"Region":  e.Region,
				"Message": e.Message,
			}
			fcTable.Rows = append(fcTable.Rows, row)
		}
	}

	v.Resources = append(CISCompliance.Resources, fcTable, infoTable)

	v.Details = fmt.Sprintf("Account: %s\n", alias)
	v.Details += "\n"
	v.Details += fmt.Sprintf("Passed: %d\n", len(passed))
	v.Details += fmt.Sprintf("Failed: %d\n", len(failed))
	v.Details += fmt.Sprintf("Info: %d\n", len(info))

	if len(failed) > 0 {
		v.Score = report.SeverityThresholdLow
	}

	state.AddVulnerabilities(v)
}

type assumeRoleResponse struct {
	AccessKey       string `json:"access_key"`
	SecretAccessKey string `json:"secret_access_key"`
	SessionToken    string `json:"session_token"`
}

func loadCredentials(url string, accountID, role string, sessionDuration int) error {
	m := map[string]interface{}{"account_id": accountID}
	if role != "" {
		m["role"] = role
	}
	if sessionDuration != 0 {
		m["duration"] = sessionDuration
	}
	jsonBody, err := json.Marshal(m)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	buf, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var r assumeRoleResponse
	err = json.Unmarshal(buf, &r)
	if err != nil {
		logger.Errorf("can not decode response body '%s'", string(buf))
		return err
	}

	if err := os.Setenv(envKeyID, r.AccessKey); err != nil {
		return err
	}

	if err := os.Setenv(envKeySecret, r.SecretAccessKey); err != nil {
		return err
	}

	if err := os.Setenv(envToken, r.SessionToken); err != nil {
		return err
	}

	return nil
}

// accountAlias gets one of the current aliases for the account that the
// credentials passed belong to.
func accountAlias(creds *credentials.Credentials) (string, error) {
	svc := iam.New(session.New(&aws.Config{Credentials: creds}))
	resp, err := svc.ListAccountAliases(&iam.ListAccountAliasesInput{})
	if err != nil {
		return "", err
	}
	if len(resp.AccountAliases) == 0 {
		logger.Warn("No aliases found for the account")
		return "", nil
	}
	a := resp.AccountAliases[0]
	if a == nil {
		return "", errors.New("unexpected nil getting aliases for aws account")
	}
	return *a, nil
}
