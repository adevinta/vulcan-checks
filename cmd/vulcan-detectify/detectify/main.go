package detectify

import (
	"assetsOwnership"
	"context"
	"fmt"
	"utils"

	checkstate "github.com/adevinta/vulcan-check-sdk/state"
)

// Initial function starting the flow of Detectify process
func Run(ctx context.Context, targetDomain string, state checkstate.State) error {

	detectifyClient := newDetectifyClientBuilder(state)
	detectifyClient.vulcanTarget = targetDomain

	assetsOwnershipMap, err := assetsOwnership.OwnershipMap(detectifyClient.vulcanTarget)
	if err != nil {
		utils.PrintLogs(fmt.Sprintf("[StartDetectifyCheck] %s", err.Error()))
		return err
	}
	for _, item := range assetsOwnershipMap {
		utils.PrintLogs(fmt.Sprintf("[%s] %s", item.Owner, item.Name))
		detectifyClient.teamKey = item.OwnerKey
		detectifyClient.domainName = item.Name
		detectifyClient.assetToken = item.UUID
		err = detectifyClient.collectTargetVulnerbilities()
		if err != nil {
			utils.PrintLogs(err.Error())

		}
		err = detectifyClient.collectSubDomainsVulnerbilities()
		if err != nil {
			utils.PrintLogs(err.Error())

		}
	}
	// store collected vulnerabilities
	detectifyClient.storeDetectifyVulns()

	return nil
}

// Collect Target Vulnerabilities
func (detectifyClient *detectifyCheckAgent) collectTargetVulnerbilities() error {

	utils.PrintLogs(fmt.Sprintf("[collectVulnerbilities] Collecting %s Detectify Vulnerabilities", detectifyClient.domainName))
	// Collecting vulnerabilities
	detectifyVulnerabilities, err := detectifyClient.listAssetVulnerabilities()
	if err != nil {
		utils.PrintLogs(fmt.Sprintf("[collectVulnerbilities] ListAssetsVulnerabilities Error: %s", err.Error()))
		return err
	}
	err = detectifyClient.reportVulnerabilities(detectifyVulnerabilities)
	if err != nil {
		utils.PrintLogs(fmt.Sprintf("[collectVulnerbilities] reportVulnerabilities Error: %s", err.Error()))

		return err
	}
	return nil
}

// Collect subdomains' vulnerabilities associated with the target uuid/token
func (detectifyClient *detectifyCheckAgent) collectSubDomainsVulnerbilities() error {

	// Add Subdomains and their UUIDs to the Target list
	targets, err := detectifyClient.listSubDomains()
	if err != nil {
		utils.PrintLogs(fmt.Sprintf("[collectSubDomainsVulnerbilities] ListSubDomains Errors: %s", err.Error()))
		return err
	}

	// Collecting vulnerabilities
	for _, asset := range targets {
		utils.PrintLogs(fmt.Sprintf("[collectSubDomainsVulnerbilities] %s : %s", asset.Name, asset.UUID))
		detectifyClient.domainName = asset.Name
		detectifyClient.assetToken = asset.UUID
		detectifyClient.pageSize = defaultPageSize
		// Collecting vulnerabilities
		detectifyVulnerabilities, err := detectifyClient.listAssetVulnerabilities()
		if err != nil {
			utils.PrintLogs(fmt.Sprintf("[collectSubDomainsVulnerbilities] ListAssetsVulnerabilities Errors: %s", err.Error()))
			return err
		}
		err = detectifyClient.reportVulnerabilities(detectifyVulnerabilities)
		if err != nil {
			utils.PrintLogs(fmt.Sprintf("[collectSubDomainsVulnerbilities] reportVulnerabilities Error: %s", err.Error()))

			return err
		}

	}

	return nil
}
