package assetsOwnership

import (
	"fmt"
	"net/http"
	"utils"
)

// Perform HTTP Request to Lambda
func assetsHTTPRequest(client *http.Client, httpMethod, apiURL, message, xApiKey string) ([]byte, error) {
	assetsMgmtHeader := map[string]string{
		"Content-Type": "application/json",
		"User-Agent":   userAgent,
		"x-api-key":    xApiKey,
	}
	apiURL = fmt.Sprintf("%s?%s", apiURL, message)

	body, err := utils.PerformHTTPRequest(client, httpMethod, apiURL, "", assetsMgmtHeader)
	if err != nil {
		utils.PrintLogs(fmt.Sprintf("[assetsHTTPRequest] %s Error: %s", apiURL, err.Error()))
		return nil, err
	}
	return body, nil
}
