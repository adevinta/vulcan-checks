/*
Copyright 2020 Adevinta
*/

package main

import (
	"context"
	"fmt"
	"os"

	check "github.com/adevinta/vulcan-check-sdk"
	checkstate "github.com/adevinta/vulcan-check-sdk/state"
	"github.com/adevinta/vulcan-checks/internal/awshelpers"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go/aws/arn"
)

var checkName = "vulcan-aws-alerts"

func main() {
	run := func(ctx context.Context, target, assetType, optJSON string, state checkstate.State) error {
		logger := check.NewCheckLog(checkName)

		parsedARN, err := arn.Parse(target)
		if err != nil {
			return fmt.Errorf("unable to parse ARN: %w", err)
		}
		assumeRoleEndpoint := os.Getenv("VULCAN_ASSUME_ROLE_ENDPOINT")
		roleName := os.Getenv("ROLE_NAME")

		var cfg aws.Config
		if assumeRoleEndpoint == "" {
			cfg, err = awshelpers.GetAwsConfig(target, roleName, 3600)
		} else {
			cfg, err = awshelpers.GetAwsConfigWithVulcanAssumeRole(assumeRoleEndpoint, parsedARN.AccountID, roleName, 3600)

		}
		if err != nil {
			logger.Errorf("unable to get AWS config: %v", err)
			return checkstate.ErrAssetUnreachable
		}

		return caCertificateRotation(logger, cfg, parsedARN.AccountID, state)
	}
	c := check.NewCheckFromHandler(checkName, run)
	c.RunAndServe()
}
