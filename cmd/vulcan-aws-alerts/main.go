/*
Copyright 2020 Adevinta
*/

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/sirupsen/logrus"

	check "github.com/adevinta/vulcan-check-sdk"
	checkstate "github.com/adevinta/vulcan-check-sdk/state"
	"github.com/aws/aws-sdk-go/aws/arn"
)

const checkName = "vulcan-aws-alerts"

func main() {
	run := func(ctx context.Context, target, assetType, optJSON string, state checkstate.State) error {
		logger := check.NewCheckLogFromContext(ctx, checkName)

		if target == "" {
			return fmt.Errorf("check target missing")
		}

		assumeRoleEndpoint := os.Getenv("VULCAN_ASSUME_ROLE_ENDPOINT")
		role := os.Getenv("ROLE_NAME")

		parsedARN, err := arn.Parse(target)
		if err != nil {
			return err
		}
		var cfg aws.Config
		var creds aws.Credentials
		if assumeRoleEndpoint != "" {
			c, err := getCredentials(assumeRoleEndpoint, parsedARN.AccountID, role, logger)
			if err != nil {
				if errors.Is(err, errNoCredentials) {
					return checkstate.ErrAssetUnreachable
				}
				return err
			}
			creds = *c
		} else {
			// try to access with the default credentials
			// TODO: Review when the error should be an checkstate.ErrAssetUnreachable (INCONCLUSIVE)
			cfg, err = config.LoadDefaultConfig(context.Background(), config.WithRegion("us-east-1"))
			if err != nil {
				return fmt.Errorf("unable to create AWS config: %w", err)
			}
			stsSvc := sts.NewFromConfig(cfg)
			roleArn := fmt.Sprintf("arn:aws:iam::%s:role/%s", parsedARN.AccountID, role)
			prov := stscreds.NewAssumeRoleProvider(stsSvc, roleArn)
			creds, err = prov.Retrieve(context.Background())
			if err != nil {
				return fmt.Errorf("unable to assume role: %w", err)
			}
		}

		credsProvider := credentials.NewStaticCredentialsProvider(creds.AccessKeyID, creds.SecretAccessKey, creds.SessionToken)
		cfg, err = config.LoadDefaultConfig(context.Background(),
			config.WithRegion("us-east-1"),
			config.WithCredentialsProvider(credsProvider),
		)
		if err != nil {
			return fmt.Errorf("unable to create AWS config: %w", err)
		}

		// Validate that the account id in the target ARN matches the account id in the credentials
		if req, err := sts.NewFromConfig(cfg).GetCallerIdentity(context.TODO(), &sts.GetCallerIdentityInput{}); err != nil {
			return fmt.Errorf("unable to get caller identity: %w", err)
		} else if *req.Account != parsedARN.AccountID {
			return fmt.Errorf("account id in target ARN does not match the account id in the credentials (target ARN: %s, credentials account id: %s)", parsedARN.AccountID, *req.Account)
		}

		return caCertificateRotation(logger, cfg, parsedARN.AccountID, state)
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

var errNoCredentials = errors.New("unable to decode credentials")

func getCredentials(url string, accountID, role string, logger *logrus.Entry) (*aws.Credentials, error) {
	m := map[string]any{"account_id": accountID, "duration": 3600}
	if role != "" {
		m["role"] = role
	}
	jsonBody, err := json.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("unable to marshal assume role request body for account %s: %w", accountID, err)
	}
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("unable to create request for the assume role service: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		logger.Errorf("cannot do request: %s", err.Error())
		return nil, err
	}
	defer resp.Body.Close() // nolint

	assumeRoleResponse := AssumeRoleResponse{}
	buf, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Errorf("can not read request body %s", err.Error())
		return nil, err
	}

	err = json.Unmarshal(buf, &assumeRoleResponse)
	if err != nil {
		logger.Errorf("Cannot decode request: %s", err.Error())
		logger.Errorf("ResponseBody: %s", string(buf))
		return nil, errNoCredentials
	}
	return &aws.Credentials{
		AccessKeyID:     assumeRoleResponse.AccessKey,
		SecretAccessKey: assumeRoleResponse.SecretAccessKey,
		SessionToken:    assumeRoleResponse.SessionToken,
	}, nil
}
