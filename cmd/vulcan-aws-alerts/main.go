/*
Copyright 2021 Adevinta
*/

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/aws/aws-sdk-go/aws/credentials"

	check "github.com/adevinta/vulcan-check-sdk"
	"github.com/adevinta/vulcan-check-sdk/helpers"
	checkstate "github.com/adevinta/vulcan-check-sdk/state"
	"github.com/aws/aws-sdk-go/aws/arn"
)

var (
	checkName = "vulcan-aws-alerts"
	logger    = check.NewCheckLog(checkName)
)

func main() {
	run := func(ctx context.Context, target, assetType, optJSON string, state checkstate.State) error {
		if target == "" {
			return fmt.Errorf("check target missing")
		}

		vulcanAssumeRoleEndpoint := os.Getenv("VULCAN_ASSUME_ROLE_ENDPOINT")
		if vulcanAssumeRoleEndpoint == "" {
			return fmt.Errorf("VULCAN_ASSUME_ROLE_ENDPOINT option is missing")
		}
		roleName := os.Getenv("ROLE_NAME")

		isReachable, err := helpers.IsReachable(target, assetType,
			helpers.NewAWSCreds(vulcanAssumeRoleEndpoint, roleName))
		if err != nil {
			logger.Warnf("Can not check asset reachability: %v", err)
		}
		if !isReachable {
			return checkstate.ErrAssetUnreachable
		}

		parsedARN, err := arn.Parse(target)
		if err != nil {
			return err
		}

		return caCertificateRotation(parsedARN.AccountID, vulcanAssumeRoleEndpoint, roleName, state)
	}
	c := check.NewCheckFromHandler(checkName, run)
	c.RunAndServe()
}

// AssumeRoleResponse represent a response from vulcan-assume-role
type AssumeRoleResponse struct {
	AccessKey       string `json:"access_key"`
	SecretAccessKey string `json:"secret_access_key"`
	SessionToken    string `json:"session_token"`
}

func getCredentials(url string, accountID, role string) (*credentials.Credentials, error) {
	m := map[string]string{"account_id": accountID}
	if role != "" {
		m["role"] = role
	}
	jsonBody, err := json.Marshal(m)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		logger.Errorf("cannot do request: %s", err.Error())
		return nil, err
	}
	defer resp.Body.Close()

	assumeRoleResponse := AssumeRoleResponse{}
	buf, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		logger.Errorf("Cannot read request body %s", err.Error())
		return nil, err
	}

	err = json.Unmarshal(buf, &assumeRoleResponse)
	if err != nil {
		logger.Errorf("Cannot decode request %s", err.Error())
		logger.Errorf("RequestBody: %s", string(buf))
		return nil, err
	}

	return credentials.NewStaticCredentials(
		assumeRoleResponse.AccessKey,
		assumeRoleResponse.SecretAccessKey,
		assumeRoleResponse.SessionToken), nil
}
