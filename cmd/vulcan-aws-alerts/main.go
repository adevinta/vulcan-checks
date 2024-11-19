/*
Copyright 2020 Adevinta
*/

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/sirupsen/logrus"

	check "github.com/adevinta/vulcan-check-sdk"
	"github.com/adevinta/vulcan-check-sdk/helpers"
	checkstate "github.com/adevinta/vulcan-check-sdk/state"
	"github.com/aws/aws-sdk-go/aws/arn"
)

const checkName = "vulcan-aws-alerts"

func main() {
	run := func(ctx context.Context, target, assetType, optJSON string, state checkstate.State) error {
		logger := check.NewCheckLog(checkName)
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

		return caCertificateRotation(logger, parsedARN.AccountID, vulcanAssumeRoleEndpoint, roleName, state)
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

func getCredentials(logger *logrus.Entry, url string, accountID, role string) (*credentials.Credentials, error) {
	m := map[string]string{"account_id": accountID}
	if role != "" {
		m["role"] = role
	}
	jsonBody, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		logger.Errorf("cannot do request: %s", err.Error())
		return nil, err
	}
	defer resp.Body.Close()

	assumeRoleResponse := AssumeRoleResponse{}
	buf, err := io.ReadAll(resp.Body)
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
