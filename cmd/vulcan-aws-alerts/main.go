/*
Copyright 2020 Adevinta
*/

package main

import (
	"context"
	"os"

	check "github.com/adevinta/vulcan-check-sdk"
	"github.com/adevinta/vulcan-check-sdk/helpers/awshelpers"
	checkstate "github.com/adevinta/vulcan-check-sdk/state"
	"github.com/aws/aws-sdk-go-v2/aws"
)

const checkName = "vulcan-aws-alerts"

func main() {
	run := func(ctx context.Context, target, assetType, optJSON string, state checkstate.State) error {
		logger := check.NewCheckLogFromContext(ctx, checkName)

		assumeRoleEndpoint := os.Getenv("VULCAN_ASSUME_ROLE_ENDPOINT")
		roleName := os.Getenv("ROLE_NAME")

		var cfg aws.Config
		var err error
		if assumeRoleEndpoint == "" {
			cfg, err = awshelpers.GetAwsConfig(ctx, target, roleName, 3600)
		} else {
			cfg, err = awshelpers.GetAwsConfigWithVulcanAssumeRole(ctx, assumeRoleEndpoint, target, roleName, 3600)
		}
		if err != nil {
			logger.Errorf("unable to get AWS config: %v", err)
			return checkstate.ErrAssetUnreachable
		}

		return caCertificateRotation(ctx, logger, cfg, target, state)
	}
	c := check.NewCheckFromHandler(checkName, run)
	c.RunAndServe()
}
