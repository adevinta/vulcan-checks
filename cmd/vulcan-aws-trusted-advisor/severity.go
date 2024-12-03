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
	"1iG5NDGVre": {
		"Red": report.SeverityThresholdMedium,
	},

	// Amazon S3 Bucket Permissions
	"Pfx0RwqBli": {
		"Yellow": report.SeverityThresholdMedium,
		"Red":    report.SeverityThresholdHigh,
	},

	// ELB Listener Security
	"a2sEc6ILx": {
		"Yellow": report.SeverityThresholdMedium,
		"Red":    report.SeverityThresholdHigh,
	},

	// ELB Security Groups
	"xSqX82fQu": {
		"Yellow": report.SeverityThresholdNone,
		"Red":    report.SeverityThresholdNone,
	},

	// IAM Access Key Rotation
	"DqdJqYeRm5": {
		"Green":  report.SeverityThresholdNone,
		"Yellow": report.SeverityThresholdLow,
		"Red":    report.SeverityThresholdMedium,
	},

	// Security Groups - Specific Ports Unrestricted
	"HCP4007jGY": {
		"Green":  report.SeverityThresholdNone,
		"Yellow": report.SeverityThresholdLow,
		"Red":    report.SeverityThresholdMedium,
	},

	// Amazon EBS Public Snapshots
	"ePs02jT06w": {
		"Red": report.SeverityThresholdMedium,
	},

	// Amazon RDS Public Snapshots
	"rSs93HQwa1": {
		"Red": report.SeverityThresholdHigh,
	},

	// Amazon RDS Security Group Access Risk
	"nNauJisYIT": {
		"Yellow": report.SeverityThresholdLow,
		"Red":    report.SeverityThresholdMedium,
	},

	// Amazon Route 53 MX and SPF Resource Record Sets
	"c9D319e7sG": {
		"Yellow": report.SeverityThresholdMedium,
	},

	// AWS CloudTrail Logging
	"vjafUGJ9H0": {
		"Yellow": report.SeverityThresholdLow,
		"Red":    report.SeverityThresholdLow,
	},

	// CloudFront Custom SSL Certificates in the IAM Certificate Store
	"N425c450f2": {
		"Yellow": report.SeverityThresholdMedium,
		"Red":    report.SeverityThresholdMedium,
	},

	// CloudFront SSL Certificate on the Origin Server
	"N430c450f2": {
		"Yellow": report.SeverityThresholdMedium,
		"Red":    report.SeverityThresholdMedium,
	},

	// Exposed Access Keys
	"12Fnkpl8Y5": {
		"Red": report.SeverityThresholdCritical,
	},

	// IAM Password Policy
	"Yw2K9puPzl": {
		"Yellow": report.SeverityThresholdNone,
		"Red":    report.SeverityThresholdNone,
	},

	// IAM Use
	"zXCkfM1nI3": {
		"Yellow": report.SeverityThresholdNone,
	},

	// MFA on Root Account
	"7DAFEmoDos": {
		"Red": report.SeverityThresholdLow,
	},
}
