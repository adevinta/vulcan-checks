/*
Copyright 2025 Adevinta
*/

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/sirupsen/logrus"
)

type CredentialsService struct {
	logger *logrus.Entry
}

func NewCredentialsService(logger *logrus.Entry) *CredentialsService {
	return &CredentialsService{logger: logger}
}

// AssumeRoleResponse represent a response from vulcan-assume-role
type AssumeRoleResponse struct {
	AccessKey       string `json:"access_key"`
	SecretAccessKey string `json:"secret_access_key"`
	SessionToken    string `json:"session_token"`
}

var ErrNoCredentials = errors.New("unable to decode credentials")

func (cs CredentialsService) GetCredentials(url string, accountID, role string) (*aws.Credentials, error) {
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
		cs.logger.Error(fmt.Sprintf("cannot do request: %s", err.Error()))
		return nil, err
	}
	defer resp.Body.Close() // nolint

	assumeRoleResponse := AssumeRoleResponse{}
	buf, err := io.ReadAll(resp.Body)
	if err != nil {
		cs.logger.Error(fmt.Sprintf("can not read request body %s", err.Error()))
		return nil, err
	}

	err = json.Unmarshal(buf, &assumeRoleResponse)
	if err != nil {
		cs.logger.Error("Cannot decode request",
			slog.String("error", err.Error()),
			slog.String("body", string(buf)),
		)
		return nil, ErrNoCredentials
	}
	return &aws.Credentials{
		AccessKeyID:     assumeRoleResponse.AccessKey,
		SecretAccessKey: assumeRoleResponse.SecretAccessKey,
		SessionToken:    assumeRoleResponse.SessionToken,
	}, nil
}
