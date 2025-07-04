/*
Copyright 2019 Adevinta
*/
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	check "github.com/adevinta/vulcan-check-sdk"
	"github.com/adevinta/vulcan-check-sdk/helpers"
	"github.com/adevinta/vulcan-check-sdk/helpers/awshelpers"
	checkstate "github.com/adevinta/vulcan-check-sdk/state"
	report "github.com/adevinta/vulcan-report"
	awsRetry "github.com/aws/aws-sdk-go-v2/aws/retry"
	supporttypes "github.com/aws/aws-sdk-go-v2/service/support/types"
	"golang.org/x/time/rate"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/support"
	"github.com/sirupsen/logrus"
)

const (
	tagRecommendedAction   = `<h4 class='headerBodyStyle'>Recommended Action</h4>`
	tagAdditionalResources = `<h4 class='headerBodyStyle'>Additional Resources</h4>`
	checkName              = "vulcan-aws-trusted-advisor"
)

var (
	additionalResourcesPattern = regexp.MustCompile(`href=\"(?P<resource>.*?)\"`)
	templateResource           = "$resource"

	rfrshInterval = time.Duration(5 * time.Second)

	// Words to capture for the AffectedResourceString.
	captureWords = []string{
		"Region",
		"Snapshot",
		"Volume",
		"DB Instance",
		"Security Group",
		"Hosted Zone",
		"Record Set",
		"Bucket",
		"Trail",
		"Function",
		"Certificate",
		"Origin",
		"Load Balancer",
		"Access Key",
		"User",
		"Password Policy",
	}
)

type options struct {
	RefreshTimeout int `json:"refresh_timeout"`
}

func main() {
	run := func(ctx context.Context, target, assetType, optJSON string, state checkstate.State) error {
		logger := check.NewCheckLogFromContext(ctx, checkName)
		var opt options
		opt.RefreshTimeout = 5
		if optJSON != "" {
			if err := json.Unmarshal([]byte(optJSON), &opt); err != nil {
				return err
			}
		}
		if target == "" {
			return fmt.Errorf("check target missing")
		}

		return scanAccount(ctx, opt, target, assetType, logger, state)
	}
	c := check.NewCheckFromHandler(checkName, run)
	c.RunAndServe()
}

func extractLinesFromHTML(htmlText string) []string {
	result := []string{}

	for _, line := range strings.Split(htmlText, "<br>") {
		line = strings.Replace(line, "\n", "", -1)
		line = strings.Replace(line, "<br>", "", -1)
		line = strings.Replace(line, "<br/>", "", -1)
		line = strings.Replace(line, "</br>", "", -1)
		if len(line) > 0 {
			result = append(result, line)
		}
	}
	return result
}

func scanAccount(ctx context.Context, opt options, target, _ string, logger *logrus.Entry, state checkstate.State) error {
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

	s := support.NewFromConfig(cfg, func(o *support.Options) {
		o.Retryer = awsRetry.AddWithMaxAttempts(o.Retryer, 5)
	})
	// Retrieve checks list
	checks, err := s.DescribeTrustedAdvisorChecks(
		ctx,
		&support.DescribeTrustedAdvisorChecksInput{
			Language: aws.String("en"),
		})
	if err != nil {
		return err
	}

	// Refresh checks
	limiter := rate.NewLimiter(rate.Every(100*time.Millisecond), 1)
	toPoll, err := refreshSecurityChecks(ctx, s, checks.Checks, limiter, logger)
	if err != nil {
		return err
	}

	// Poll refresh statuses with a timeout
	if len(toPoll) > 0 {
		ctxTimeout, cancel := context.WithTimeout(ctx, time.Duration(opt.RefreshTimeout)*time.Second)
		defer cancel()

		pollRefreshStatuses(ctxTimeout, s, toPoll, rfrshInterval, logger)
	}

	// Retrieve checks summaries
	var alias *string
	captureWordsRegexp, err := regexp.Compile(strings.Join(captureWords, "|"))
	if err != nil {
		return err
	}

	for _, v := range checks.Checks {
		// Ignore results if we can't know the category
		if v.Category == nil {
			continue
		}

		// Ignore results that does are not security
		if *v.Category != "security" {
			continue
		}

		// Ignore results if we can't know the ID
		if v.Id == nil {
			continue
		}

		var checkSummaries *support.DescribeTrustedAdvisorCheckSummariesOutput
		checkSummaries, err = s.DescribeTrustedAdvisorCheckSummaries(
			ctx, &support.DescribeTrustedAdvisorCheckSummariesInput{
				CheckIds: []*string{v.Id},
			})
		if err != nil {
			return err
		}

		for _, summary := range checkSummaries.Summaries {
			// Only process summaries that has flagged resources.
			if !summary.HasFlaggedResources {
				continue
			}

			action := ""
			recommendedActions := []string{}
			additionalResources := []string{}

			// Avoid nil pointer dereference when reading *v.Description
			// description, recommendedActions and additionalResources will be
			// considered empty.
			if v.Description != nil {
				iRecommendedAction := strings.Index(*v.Description, tagRecommendedAction)
				if iRecommendedAction < 0 {
					// No recommended actions
					continue
				}
				iAdditionalResources := strings.Index(*v.Description, tagAdditionalResources)
				// Extract recommendedActions
				if iAdditionalResources >= iRecommendedAction+len(tagRecommendedAction) {
					recommendedActions = extractLinesFromHTML(string(*v.Description)[iRecommendedAction+len(tagRecommendedAction) : iAdditionalResources])

					// Extract additionalResources
					additionalResourcesText := string(*v.Description)[iAdditionalResources+len(tagAdditionalResources):]
					for _, submatches := range additionalResourcesPattern.FindAllStringSubmatchIndex(additionalResourcesText, -1) {
						r := []byte{}
						r = additionalResourcesPattern.ExpandString(r, templateResource, additionalResourcesText, submatches)
						additionalResources = append(additionalResources, string(r))
					}
				} else {
					recommendedActions = extractLinesFromHTML(string(*v.Description)[iRecommendedAction+len(tagRecommendedAction):])
				}
			}

			var checkResults *support.DescribeTrustedAdvisorCheckResultOutput
			checkResults, err = s.DescribeTrustedAdvisorCheckResult(ctx, &support.DescribeTrustedAdvisorCheckResultInput{CheckId: v.Id})
			if err != nil {
				return err
			}

			for _, fr := range checkResults.Result.FlaggedResources {
				// Ignore resources that have been marked as suppressed/excluded
				if fr.IsSuppressed {
					logger.Debugf("resource with ResourceID: %s have been marked as excluded", *fr.ResourceId)
					continue
				}
				// Get the alias of the account only if we did not get previously.
				if alias == nil {
					res, err := awshelpers.GetAccountAlias(ctx, cfg)
					if err != nil {
						return err
					}
					alias = &res
				}

				// Alias can not be nil because the protection before.
				row := map[string]string{"Account": *alias}
				header := []string{"Account"}
				affectedResourceStr := ""
				score := float32(0.0)
				for i := 0; i < len(v.Metadata); i++ {
					fieldName := ""
					if v.Metadata[i] != nil {
						fieldName = *v.Metadata[i]
					}
					value := ""
					if fr.Metadata[i] != nil {
						value = *fr.Metadata[i]
					}

					if fieldName == "Status" {
						score = severityMap[*v.Id][value]
						continue
					}

					if v.Metadata[i] != nil && fr.Metadata[i] != nil {
						row[fieldName] = value
						header = append(header, fieldName)

						// We are capturing just a reduced set of the metadata
						// attributes to be used in the AffectedResourceString
						// field. Mostly those that by their name seem to
						// describe where the actual problem being raised lays.
						if captureWordsRegexp.MatchString(fieldName) {
							affectedResourceStr = fmt.Sprintf("%s%s: %s | ", affectedResourceStr, strings.ReplaceAll(fieldName, " ", ""), value)
						}
					}
				}
				affectedResourceStr = strings.TrimSuffix(affectedResourceStr, " | ")

				occurrences := report.ResourcesGroup{
					Name: "Occurrences",
				}
				occurrences.Rows = append(occurrences.Rows, row)
				occurrences.Header = header

				summary := ""
				// Avoid nil pointer dereference when reading *v.Name
				if v.Name != nil {
					summary = "AWS " + *v.Name
				}
				resourceID := ""
				if fr.ResourceId != nil {
					resourceID = *fr.ResourceId
				}
				vuln := report.Vulnerability{
					Summary:     summary,
					Description: action,
					Score:       score,
					// AWS Trusted Advisor provides already an ID generated by
					// them, that seems the best option to indicate which is
					// the affected resource of the finding. However, that
					// field is not very friendly to be shown in the UI, and
					// therefore we are using a set of the metadata values
					// provided by their checks in the AffectedResourceString
					// attribute.
					AffectedResource:       resourceID,
					AffectedResourceString: affectedResourceStr,
					Labels:                 []string{"issue", "aws"},
					Resources:              []report.ResourcesGroup{occurrences},
				}
				vuln.Recommendations = append(vuln.Recommendations, recommendedActions...)
				vuln.References = append(vuln.References, additionalResources...)

				// Doesn't seem to be any useful field to feed the fingerprint
				// of the finding.
				vuln.Fingerprint = helpers.ComputeFingerprint()

				state.AddVulnerabilities(vuln)
			}
		}
	}
	return err
}

func refreshSecurityChecks(ctx context.Context, svc *support.Client, checks []supporttypes.TrustedAdvisorCheckDescription, limiter *rate.Limiter, logger *logrus.Entry) ([]*string, error) {
	var enqueuedIDs []*string

	for _, chk := range checks {
		if chk.Category == nil || *chk.Category != "security" {
			continue
		}

		if err := limiter.Wait(ctx); err != nil {
			return nil, fmt.Errorf("rate limiter interrupted: %w", err)
		}

		out, err := svc.RefreshTrustedAdvisorCheck(ctx, &support.RefreshTrustedAdvisorCheckInput{
			CheckId: chk.Id,
		})
		if err != nil {
			if strings.Contains(err.Error(), "InvalidParameterValueException") {
				logger.Warnf("check %q is not refreshable, ignoring", *chk.Name)
				continue
			}
			return nil, fmt.Errorf("refresh %s: %w", *chk.Id, err)
		}
		status := aws.ToString(out.Status.Status)
		logger.Infof("refresh of %q check with status %s", *chk.Name, status)
		if status == "enqueued" {
			enqueuedIDs = append(enqueuedIDs, chk.Id)
		}
	}

	return enqueuedIDs, nil
}

func pollRefreshStatuses(ctx context.Context, svc *support.Client, ids []*string, maxRefreshWaitInterval time.Duration, logger *logrus.Entry) {
	for {
		select {
		case <-ctx.Done():
			logger.Warnf("maxRefreshWaitInterval reached, stop polling")
			return
		default:
			out, err := svc.DescribeTrustedAdvisorCheckRefreshStatuses(ctx, &support.DescribeTrustedAdvisorCheckRefreshStatusesInput{
				CheckIds: ids,
			})
			if err != nil {
				logger.Errorf("DescribeTrustedAdvisorCheckRefreshStatuses failed: %v", err)
				return
			}

			var maxSleep time.Duration
			var pending bool

			for _, st := range out.Statuses {
				s := aws.ToString(st.Status)
				if s == "enqueued" || s == "processing" {
					pending = true

					if st.MillisUntilNextRefreshable != 0 {
						d := time.Duration(st.MillisUntilNextRefreshable) * time.Millisecond
						if d > maxSleep {
							maxSleep = d
						}
					}
				}
			}

			if !pending {
				return
			}

			if maxSleep <= 0 {
				maxSleep = maxRefreshWaitInterval
			}
			logger.Infof("waiting %s until next check", maxSleep)
			select {
			case <-time.After(maxSleep):
			case <-ctx.Done():
			}
		}
	}
}
