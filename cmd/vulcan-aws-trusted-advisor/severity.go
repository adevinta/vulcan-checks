/*
Copyright 2019 Adevinta
*/

package main

import (
	report "github.com/adevinta/vulcan-report"
)

// Information extracted from: https://aws.amazon.com/premiumsupport/ta-iam/
var severityMap = map[string]map[string]float32{

	// Security Groups - Unrestricted Access
	"1iG5NDGVre": map[string]float32{
		"Red": report.SeverityThresholdMedium,
	},

	// Amazon S3 Bucket Permissions
	"Pfx0RwqBli": map[string]float32{
		"Yellow": report.SeverityThresholdMedium,
		"Red":    report.SeverityThresholdHigh,
	},

	// ELB Listener Security
	"a2sEc6ILx": map[string]float32{
		"Yellow": report.SeverityThresholdMedium,
		"Red":    report.SeverityThresholdHigh,
	},

	// ELB Security Groups
	"xSqX82fQu": map[string]float32{
		"Yellow": report.SeverityThresholdNone,
		"Red":    report.SeverityThresholdNone,
	},

	// IAM Access Key Rotation
	"DqdJqYeRm5": map[string]float32{
		"Green":  report.SeverityThresholdNone,
		"Yellow": report.SeverityThresholdLow,
		"Red":    report.SeverityThresholdMedium,
	},

	// Security Groups - Specific Ports Unrestricted
	"HCP4007jGY": map[string]float32{
		"Green":  report.SeverityThresholdNone,
		"Yellow": report.SeverityThresholdLow,
		"Red":    report.SeverityThresholdMedium,
	},

	// Amazon EBS Public Snapshots
	"ePs02jT06w": map[string]float32{
		"Red": report.SeverityThresholdMedium,
	},

	// Amazon RDS Public Snapshots
	"rSs93HQwa1": map[string]float32{
		"Red": report.SeverityThresholdHigh,
	},

	// Amazon RDS Security Group Access Risk
	"nNauJisYIT": map[string]float32{
		"Yellow": report.SeverityThresholdLow,
		"Red":    report.SeverityThresholdMedium,
	},

	// Amazon Route 53 MX and SPF Resource Record Sets
	"c9D319e7sG": map[string]float32{
		"Yellow": report.SeverityThresholdMedium,
	},

	// AWS CloudTrail Logging
	"vjafUGJ9H0": map[string]float32{
		"Yellow": report.SeverityThresholdLow,
		"Red":    report.SeverityThresholdLow,
	},

	// CloudFront Custom SSL Certificates in the IAM Certificate Store
	"N425c450f2": map[string]float32{
		"Yellow": report.SeverityThresholdMedium,
		"Red":    report.SeverityThresholdMedium,
	},

	// CloudFront SSL Certificate on the Origin Server
	"N430c450f2": map[string]float32{
		"Yellow": report.SeverityThresholdMedium,
		"Red":    report.SeverityThresholdMedium,
	},

	// Exposed Access Keys
	"12Fnkpl8Y5": map[string]float32{
		"Red": report.SeverityThresholdCritical,
	},

	// IAM Password Policy
	"Yw2K9puPzl": map[string]float32{
		"Yellow": report.SeverityThresholdNone,
		"Red":    report.SeverityThresholdNone,
	},

	// IAM Use
	"zXCkfM1nI3": map[string]float32{
		"Yellow": report.SeverityThresholdNone,
	},

	// MFA on Root Account
	"7DAFEmoDos": map[string]float32{
		"Red": report.SeverityThresholdLow,
	},
}
