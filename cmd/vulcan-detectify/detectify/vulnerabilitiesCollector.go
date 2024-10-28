package detectify

import (
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"utils"

	"github.com/adevinta/vulcan-check-sdk/helpers"
	report "github.com/adevinta/vulcan-report"
)

// Exported: False :::::
// Returns vulnerabilities according to the provided filter settings, provided as query parameters.
// The response is paginated. If the number of total vulnerabilities with the current filter settings exceeds the page size,
// the response will contain the field has_more that will be true. The field next_marker contains a UUID to pass using the marker parameter,
// which will be the offset for the next page.
// Example: .../vulnerabilities/?severity[]=high&severity[]=medium
// Target API: https://api.detectify.com/rest/v2/vulnerabilities/
// assetHost used instead of assetToken because location param contains the host (domain/subdomain) , while the token is always set to the top domain's token. Vulcan pass hosts
func (detectifyClient *detectifyCheckAgent) nextPageAssetVulnerabilities() ([]byte, error) {
	vulnURL := fmt.Sprintf("%s/vulnerabilities/?host[]=%s&pageSize=%d", BaseURL, detectifyClient.domainName, detectifyClient.pageSize)
	// First Call won't have pageMarker parameter in url
	if detectifyClient.pageMarker != "" {
		vulnURL = fmt.Sprintf("%s&marker=%s", vulnURL, detectifyClient.pageMarker)
	}
	// set all status of interest
	for _, state := range detectifyClient.vulnStatus {
		vulnURL = fmt.Sprintf("%s&status[]=%s", vulnURL, state)
	}

	// Read response body
	body, err := sendDetectifyAPIRequest(detectifyClient.client, "GET", vulnURL, detectifyClient.teamKey)
	if err != nil {
		return nil, err
	}
	return body, nil
}

// Exported: False :::::
// Iterates on Vulnerabilities Pages and returns vulnerabilities according to the provided filter settings, provided as query parameters.
// The response is paginated. If the number of total vulnerabilities with the current filter settings exceeds the page size,
// the response will contain the field has_more that will be true. The field next_marker contains a UUID to pass using the marker parameter,
// which will be the offset for the next page.
// Example: .../vulnerabilities/?status[]=active&host[]=
// Target API: https://api.detectify.com/rest/v2/vulnerabilities/
func (detectifyClient *detectifyCheckAgent) listAssetVulnerabilities() ([]Vulnerability, error) {

	if detectifyClient.pageSize == 0 {
		// maximum
		detectifyClient.pageSize = defaultPageSize
	}
	// Status of a vulnerability.

	var vulns []Vulnerability
	var vulnsPage VulnerabilityPage
	for {
		detectifyClient.pageMarker = vulnsPage.NextMarker
		body, err := detectifyClient.nextPageAssetVulnerabilities()
		if err != nil {
			utils.PrintLogs(fmt.Sprintf("Error: %s", err.Error()))
			return nil, err
		}
		err = json.Unmarshal(body, &vulnsPage)
		if err != nil {
			utils.PrintLogs(fmt.Sprintf("Error: %s", err.Error()))
			return nil, err
		}

		vulns = append(vulns, vulnsPage.Vulnerabilities...)
		// utils.PrintLogs(fmt.Sprintf(" Fetched -> %s , Next: %t -> %s", vulnsPage.CurrentMarker, vulnsPage.HasMore, vulnsPage.NextMarker))

		if !vulnsPage.HasMore {
			break
		}

	}
	detectifyClient.resetClientMetadata()

	return vulns, nil
}

// Exported: False :::::
// FingerPrint : sha256(vulnerableLocation, vulnIDinDetectify) vulnIDinDetectify is unique a cross detectify
// Prepare reported Vulnerabilities schema to match Vulcan schema
func (detectifyClient *detectifyCheckAgent) reportVulnerabilities(vulnerabilities []Vulnerability) error {
	utils.PrintLogs(fmt.Sprintf("[reportVulnerabilities] Adding %s's Vulnerabilities [%d] ", detectifyClient.vulcanTarget, len(vulnerabilities)))
	defaultRecommendation := ""

	for _, vuln := range vulnerabilities {
		vulnDetailsTextValue := ""
		if len(vuln.Details.Text) > 0 {
			vulnDetailsTextValue = vuln.Details.Text[0].Value
		}
		vulnDetailsTextValue = vulnDetailsTextValue + ". Some text to make sure we have a details text set."
		tempHash := helpers.ComputeFingerprint(detectifyClient.vulcanTarget, vuln.VulnUUID, vuln.AssetToken, vuln.Location)
		vulnLocationRow := map[string]string{
			"Location":          vuln.Location,
			"FirstTimeDetected": vuln.CreatedAt,
			"LastTimeDetected":  vuln.UpdatedAt,
			"Status":            vuln.Status,
			"CVSSScore":         fmt.Sprintf("%.1f", math.Floor(vuln.CVSSScores.CVSS30.Score)),
		}
		// If Summary exist, add the affected resources location
		if item, ok := detectifyClient.detectifyVulns[vuln.Title]; ok {
			item.Resources[0].Rows = append(item.Resources[0].Rows, vulnLocationRow)

		} else {
			detectifyClient.detectifyVulns[vuln.Title] = (report.Vulnerability{

				AffectedResource: detectifyClient.vulcanTarget,
				Labels:           []string{"issue", "detectify", fmt.Sprintf("detectify-%s", vuln.Source.Value)},
				Fingerprint:      tempHash,
				Summary:          vuln.Title,
				Description:      fmt.Sprintf("\n%s founds %s\n\n%s", vuln.Source.Value, vuln.Definition.Title, vuln.Definition.Description),
				Details:          vulnDetailsTextValue,

				ImpactDetails: vuln.Definition.Risk,
				Score:         scoreSeverity(vuln.Severity),

				Resources: []report.ResourcesGroup{{
					Name: "Found In",
					Header: []string{
						"Location",
						"FirstTimeDetected",
						"LastTimeDetected",
						"Status",
						"CVSSScore",
					},
					Rows: []map[string]string{
						vulnLocationRow,
					},
				},
				},

				Recommendations: []string{defaultRecommendation},
				References:      []string{vuln.Links.DetailsPage},
			})
		}
	}

	return nil
}

// Exported: False :::::
// Store reported Vulnerabilities
func (detectifyClient *detectifyCheckAgent) storeDetectifyVulns() {
	for key, _ := range detectifyClient.detectifyVulns {
		detectifyClient.state.AddVulnerabilities(detectifyClient.detectifyVulns[key])
	}

}

// Exported: False :::::
// report vulnerability score match to Vulcan rating
func scoreSeverity(severityAsString string) float32 {
	severityAsString = strings.ToUpper(severityAsString)
	switch severityAsString {
	case "CRITICAL":
		return report.SeverityThresholdCritical
	case "HIGH":
		return report.SeverityThresholdHigh
	case "MODERATE":
		return report.SeverityThresholdMedium
	case "LOW":
		return report.SeverityThresholdLow
	default:
		return report.SeverityThresholdNone
	}

}
