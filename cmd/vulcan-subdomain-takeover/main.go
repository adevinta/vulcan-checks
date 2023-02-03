/*
Copyright 2023 Adevinta
*/

// vulcan-subdomain-takeover checks if an asset is vulnerable to a subdomain
// takeover according to the data in the Security Graph.
package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"time"

	check "github.com/adevinta/vulcan-check-sdk"
	checkstate "github.com/adevinta/vulcan-check-sdk/state"
	report "github.com/adevinta/vulcan-report"

	"github.com/adevinta/vulcan-checks/cmd/vulcan-subdomain-takeover/inventory"
)

const (
	name = "vulcan-subdomain-takeover"
)

var (
	logger            = check.NewCheckLog(name)
	subdomainTakeover = report.Vulnerability{
		CWEID:   284,
		Summary: "Subdomain Takeover",
		Description: "One of your DNS records points to one or more IP's that belonged to the company in the past," +
			"but they doesn't anymore, so it's very likely that the asset is vulnerable to subdomain takeover",
		Score: report.SeverityThresholdHigh,
		ImpactDetails: "An attacker may be able to claim the IP or IP's the subdomain is pointing to," +
			"so all traffic to your domain will reach the attacker controlled IP. " +
			"Potential impact includes phishing/fraud and cookie/subdomain hijacking.",
		References: []string{
			"https://www.hackerone.com/application-security/guide-subdomain-takeovers",
		},
		Recommendations: []string{
			"Remove the subdomain if it's not in use anymore",
			"Point the subdomain to an IP you control",
		},
		Labels: []string{"issue", "aws", "dns"},
	}
	// ErrNoSAssetInventoryAPIBaseURL is returned by check when no url for the
	// Security Graph asset inventory API is provided.
	ErrNoSAssetInventoryAPIBaseURL = errors.New("no base url for the Asset Inventory was provided")
)

// inventoryAPI defines the interface that an AssetInventoryAPI client must implement to be
// used by the check. This interface in introduced to make easier to test the
// check.
type inventoryAPI interface {
	Assets(typ, identifier string, validAt time.Time, pag inventory.Pagination) ([]inventory.AssetResp, error)
}

func main() {
	// Wrapping the function running the actual check allows us to specify
	// an alternative implementation of the assetInventoryAPI interface in tests.
	runner := func(ctx context.Context, target, assetType, optJSON string, state checkstate.State) error {
		return run(ctx, target, assetType, optJSON, state, nil)
	}
	c := check.NewCheckFromHandler(name, runner)
	c.RunAndServe()
}

// run implements the subdomain takeover check.
func run(ctx context.Context, target, assetType, optJSON string, state checkstate.State, inventoryClient inventoryAPI) (err error) {
	logger.Printf("Starting the %v check", name)
	if target == "" {
		return errors.New("no hostname or web address provided")
	}
	// If no asset inventory API client was provided create it using the default
	// implementation.
	if inventoryClient == nil {
		base := os.Getenv("SEC_GRAPH_INVENTORY_API_URL")
		if base == "" {
			return ErrNoSAssetInventoryAPIBaseURL
		}
		insecure := os.Getenv("SEC_GRAPH_INVENTORY_API_VERIFY") == "1"
		client, err := inventory.NewClient(base, insecure)
		if err != nil {
			return fmt.Errorf("error creating the Asset Inventory API client: %w", err)
		}
		inventoryClient = client
	}
	// The check only accepts Hostnames or WebAddresses, if the target is a
	// WebAddress we need to extract the hostname.
	host := target
	if assetType == "WebAddress" {
		host, err = hostFromWebAddress(target)
		if err != nil {
			return err
		}
	}

	addrs, err := net.LookupIP(host)
	if err != nil {
		if dnsErr, ok := err.(*net.DNSError); ok && dnsErr.IsNotFound {
			return checkstate.ErrAssetUnreachable
		}
		return fmt.Errorf("unexpected error resolving the assets: %v", err)
	}
	var expired = make(map[string]inventory.AssetResp)
	for _, addr := range addrs {
		saddr := addr.String()
		infos, err := inventoryClient.Assets("IP", saddr, time.Time{}, inventory.Pagination{})
		if err != nil {
			return fmt.Errorf("error querying the security graph asset inventory API: %w", err)
		}
		if len(infos) < 1 {
			return nil
		}
		expired[saddr] = infos[0]
	}
	// vuln := blastRadiusVuln
	// if errors.Is(err, intel.ErrAssetDoesNotExist) {
	// 	vuln.Summary = mustTemplateExecute(summaryTemplate, nil)
	// 	vuln.Details = fmt.Sprintf("There was an error calculating the blast radius: %v", err)
	// 	state.AddVulnerabilities(vuln)
	// 	return nil
	// }

	// vuln.Summary = mustTemplateExecute(summaryTemplate, brLevel(resp.Score))
	// vuln.Details = mustTemplateExecute(detailsTemplate, resp.Score)
	//state.AddVulnerabilities(vuln)
	return nil
}

func genVulnFromIPs(IPs map[string]inventory.AssetResp) report.Vulnerability {
	// The affected resource which is used to calculate the fingerprint of the vuln
	// is equal to the concatenation of the dangling IPs.
	aresource = ""

}

func hostFromWebAddress(target string) (string, error) {
	u, err := url.Parse(target)
	if err != nil {
		return "", fmt.Errorf("invalid target: %s, error: %w", target, err)
	}
	return u.Hostname(), err
}
