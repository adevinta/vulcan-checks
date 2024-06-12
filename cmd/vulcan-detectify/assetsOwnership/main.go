package assetsOwnership

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"utils"
)

// Load ApiKey and InvokeURL
func loadEnvVarConfig() error {

	envAPIKey, envAPIKeyExist = os.LookupEnv(defaultAssetsAPIENVKey)
	if !envAPIKeyExist || len(envAPIKey) == 0 {
		utils.PrintLogs("envAPIKEY")
		return utils.CustomErrors("The envAPIKey environment variable is not set", 900)
	}
	envAPIInvokeUrl, envAPIInvokeUrlExist = os.LookupEnv(defaultAssetsURLENVKey)
	if !envAPIInvokeUrlExist || len(envAPIInvokeUrl) == 0 {
		utils.PrintLogs("envAPIInvokeUrl")
		return utils.CustomErrors("The envAPIInvokeUrl environment variable is not set", 901)

	}
	return nil
}

// The main function to query asset's ownership
func OwnershipMap(targetDomain string) ([]Target, error) {

	if err := loadEnvVarConfig(); err != nil {
		utils.PrintLogs(fmt.Sprintf("[OwnershipMap] %s", err.Error()))
		return nil, err
	}

	var targets []Target
	client := &http.Client{}
	queryData := fmt.Sprintf(defaultAssetsQueryData, targetDomain)
	response, err := assetsHTTPRequest(client, defaultAssetsMethod, envAPIInvokeUrl, queryData, envAPIKey)
	if err != nil {
		utils.PrintLogs(fmt.Sprintf("[OwnershipMap] %s", err.Error()))
		return nil, err
	}

	err = json.Unmarshal([]byte(response), &targets)
	if err != nil {
		utils.PrintLogs(string(response))
		return nil, utils.CustomErrors(fmt.Sprintf("[OwnershipMap] Error %s", err.Error()), 902)
	}

	return targets, nil
}
