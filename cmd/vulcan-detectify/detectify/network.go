package detectify

import (
	"net/http"
	"utils"
)

// Perform API communication with Detectify WebService
func sendDetectifyAPIRequest(client *http.Client, httpMethod, apiURL, teamKey string) ([]byte, error) {
	detectifyHeader := map[string]string{
		"Content-Type":    "application/json",
		"User-Agent":      userAgent,
		"X-Detectify-Key": teamKey,
	}

	body, err := utils.PerformHTTPRequest(client, httpMethod, apiURL, "", detectifyHeader)
	if err != nil {
		return nil, err
	}
	return body, nil
}
