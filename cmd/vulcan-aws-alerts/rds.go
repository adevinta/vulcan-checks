/*
Copyright 2020 Adevinta
*/

package main

import (
	"context"
	"fmt"

	report "github.com/adevinta/vulcan-report"
	"github.com/sirupsen/logrus"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/rds"

	"github.com/adevinta/vulcan-check-sdk/helpers"
	"github.com/adevinta/vulcan-check-sdk/state"
)

func caCertificateRotation(ctx context.Context, logger *logrus.Entry, cfg aws.Config, target string, state state.State) error {
	parsedARN, err := arn.Parse(target)
	if err != nil {
		return fmt.Errorf("unable to parse ARN: %w", err)
	}

	rdsClient := rds.NewFromConfig(cfg)
	regions, err := rdsClient.DescribeSourceRegions(ctx, &rds.DescribeSourceRegionsInput{})
	if err != nil {
		logger.Error(err)
		return err
	}

	for _, sourceRegion := range regions.SourceRegions {
		region := *sourceRegion.RegionName
		cfg.Region = region
		rdsClient := rds.NewFromConfig(cfg)

		logger.WithField("region", region).Info("Describing pending maintenance actions on RDS")
		result, err := rdsClient.DescribePendingMaintenanceActions(ctx, &rds.DescribePendingMaintenanceActionsInput{})
		if err != nil {
			logger.Error(err)
			continue
		}
		// TODO: implement pagination
		if result.Marker != nil {
			logger.Warn("DescribePendingMaintenanceActionsWithContext returned more than 1 page")
		}
		for _, action := range result.PendingMaintenanceActions {
			for _, details := range action.PendingMaintenanceActionDetails {
				if *details.Action == "ca-certificate-rotation" {
					result, err := rdsClient.DescribeDBInstances(
						ctx,
						&rds.DescribeDBInstancesInput{
							DBInstanceIdentifier: action.ResourceIdentifier,
						})
					if err != nil {
						logger.Info(err)
						continue
					}

					for _, instance := range result.DBInstances {
						state.AddVulnerabilities(
							report.Vulnerability{
								AffectedResource: aws.ToString(instance.DBInstanceArn),
								Labels:           []string{"issue"},
								Fingerprint:      helpers.ComputeFingerprint(details.AutoAppliedAfterDate),
								Summary:          `Managed AWS databases using CA about to expire`,
								Score:            report.SeverityThresholdHigh,
								Description: `Due to the expiration of the AWS RDS CA, and to prevent downtime ` +
									`in your applications, you should add the new CA to your clients using a ` +
									`managed (i.e. RDS or Aurora) database through SSL/TLS and perform maintenance ` +
									`on the affected database instances before the certificate expiration date.`,
								References: []string{"https://aws.amazon.com/blogs/database/amazon-rds-customers-update-your-ssl-tls-certificates-by-february-5-2020/"},
								Resources: []report.ResourcesGroup{
									{
										Name:   `Instances`,
										Header: []string{"Identifier", "Account", "Region", "DBName", "Engine", "ARN", "AutoAppliedAfterDate", "CurrentApplyDate"},
										Rows: []map[string]string{
											{
												"AutoAppliedAfterDate": aws.ToTime(details.AutoAppliedAfterDate).String(),
												"CurrentApplyDate":     aws.ToTime(details.CurrentApplyDate).String(),
												"Identifier":           aws.ToString(instance.DBInstanceIdentifier),
												"Account":              parsedARN.AccountID,
												"Region":               region,
												"DBName":               aws.ToString(instance.DBName),
												"Engine":               aws.ToString(instance.Engine),
												"ARN":                  aws.ToString(instance.DBInstanceArn),
											},
										},
									},
								},
							})
					}
				}
			}
		}
	}

	return err
}
