package detectify

import (
	"encoding/json"
	"fmt"
	"utils"
)

func (detectifyClient *detectifyCheckAgent) nextPageSubdomains() ([]byte, error) {
	assetsURL := fmt.Sprintf("%s/assets/%s/subdomains/?pageSize=%d", BaseURL, detectifyClient.assetToken, detectifyClient.pageSize)
	// First Call won't have pageMarker parameter in url
	if detectifyClient.pageMarker != "" {
		assetsURL = fmt.Sprintf("%s&marker=%s", assetsURL, detectifyClient.pageMarker)
	}

	// Read response body
	body, err := sendDetectifyAPIRequest(detectifyClient.client, "GET", assetsURL, detectifyClient.teamKey)
	if err != nil {
		return nil, err
	}
	return body, nil
}

// List subdomains associated with a target token
func (detectifyClient *detectifyCheckAgent) listSubDomains() ([]Target, error) {
	utils.PrintLogs("[collectSubDomainsVulnerbilities] Added Subdomains ")
	if detectifyClient.pageSize == 0 {
		// maximum
		detectifyClient.pageSize = defaultPageSize
	}
	var subAssets SubDomains
	var targets []Target
	for {
		detectifyClient.pageMarker = subAssets.NextMarker

		body, err := detectifyClient.nextPageSubdomains()

		if err != nil {
			utils.PrintLogs(fmt.Sprintf("[ListSubDomains] nextPageSubdomains Error: %s", err.Error()))
			return nil, err
		}
		err = json.Unmarshal(body, &subAssets)
		if err != nil {
			utils.PrintLogs(fmt.Sprintf("[ListSubDomains] Unmarshal body Error: %s", err.Error()))
			return nil, err
		}
		for _, asset := range subAssets.Assets {
			tempTarget := Target{Name: asset.Name,
				UUID:     asset.Token,
				Owner:    detectifyClient.teamName,
				OwnerKey: detectifyClient.teamKey}
			targets = append(targets, tempTarget)

		}
		if !subAssets.HasMore {
			break
		}

	}
	detectifyClient.resetClientMetadata()

	return targets, nil
}
