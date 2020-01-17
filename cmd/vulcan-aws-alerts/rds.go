package main

import (
	"context"
	"fmt"

	"github.com/adevinta/vulcan-report"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/rds"
	"github.com/sirupsen/logrus"

	"github.com/adevinta/vulcan-check-sdk/state"
)

func caCertificateRotation(opt options, target string, vulcanAssumeRoleEndpoint string, roleName string, logger *logrus.Entry, state state.State) error {
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String("eu-west-1"),
	})
	if err != nil {
		return err
	}

	creds, err := getCredentials(vulcanAssumeRoleEndpoint, target, roleName, logger)
	if err != nil {
		return err
	}

	// Iterate over all AWS regions where RDS is available
	for region := range endpoints.AwsPartition().Services()[endpoints.RdsServiceID].Regions() {
		sess.Config.Region = aws.String(region)
		s := rds.New(sess, &aws.Config{Credentials: creds})

		ctx := context.Background()
		logger.Info(fmt.Sprintf("Describing pending maintenance actions on RDS for %s region", region))
		result, err := s.DescribePendingMaintenanceActionsWithContext(ctx, &rds.DescribePendingMaintenanceActionsInput{})
		if err != nil {
			logger.Error(err)
			continue
		}
		// TODO: implement pagination
		if result.Marker != nil {
			logger.Warn("DescribePendingMaintenanceActionsWithContext returned more than 1 page")
		}

		rg := report.ResourcesGroup{
			Name:   `Rotation of CA certificate`,
			Header: []string{"identifier", "account", "region", "dbname", "engine", "arn", "AutoAppliedAfterDate", "CurrentApplyDate"},
			Rows:   []map[string]string{},
		}

		v := report.Vulnerability{
			Summary:     `Rotation of CA certificate`,
			Description: `Rotation of CA certificate`,
		}

		for _, action := range result.PendingMaintenanceActions {
			for _, details := range action.PendingMaintenanceActionDetails {
				if *details.Action == "ca-certificate-rotation" {
					result, err := s.DescribeDBInstancesWithContext(
						ctx,
						&rds.DescribeDBInstancesInput{
							DBInstanceIdentifier: action.ResourceIdentifier,
						})
					if err != nil {
						logger.Error(err)
						continue
					}

					for _, instance := range result.DBInstances {
						m := make(map[string]string)
						m["AutoAppliedAfterDate"] = fmt.Sprintf("%s", *details.AutoAppliedAfterDate)
						m["CurrentApplyDate"] = fmt.Sprintf("%s", *details.CurrentApplyDate)
						m["identifier"] = *instance.DBInstanceIdentifier
						m["account"] = target
						m["region"] = region
						m["dbname"] = *instance.DBName
						m["engine"] = *instance.Engine
						m["arn"] = *instance.DBInstanceArn
						rg.Rows = append(rg.Rows, m)
					}
				}
			}
		}

		if len(rg.Rows) > 0 {
			v.Resources = []report.ResourcesGroup{rg}
			state.AddVulnerabilities(v)
		}
	}

	return err
}
