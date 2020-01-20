package main

import (
	"context"
	"fmt"

	"github.com/adevinta/vulcan-report"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/rds"

	"github.com/adevinta/vulcan-check-sdk/state"
)

func caCertificateRotation(target string, vulcanAssumeRoleEndpoint string, roleName string, state state.State) error {
	sess, err := session.NewSession(&aws.Config{})
	if err != nil {
		return err
	}

	creds, err := getCredentials(vulcanAssumeRoleEndpoint, target, roleName)
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
			Name:   `Instances`,
			Header: []string{"identifier", "account", "region", "dbname", "engine", "arn", "AutoAppliedAfterDate", "CurrentApplyDate"},
			Rows:   []map[string]string{},
		}

		v := report.Vulnerability{
			Summary: `Managed AWS databases using CA about to expire`,
			Description: `Due to the expiration of the AWS RDS CA, and to prevent downtime ` +
				`in your applications, you should add the new CA to your clients using a ` +
				`managed (i.e. RDS or Aurora) database through SSL/TLS and perform maintenance ` +
				`on the affected database instances before the certificate expiration date.`,
			References: []string{"https://aws.amazon.com/blogs/database/amazon-rds-customers-update-your-ssl-tls-certificates-by-february-5-2020/"},
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
