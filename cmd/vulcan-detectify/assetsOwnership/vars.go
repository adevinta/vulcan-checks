package assetsOwnership

const (
	userAgent              = "vulcan-detectify-client/1.0"
	defaultAssetsURLENVKey = "DETECTIFY_ASSETS_URL"
	defaultAssetsAPIENVKey = "DETECTIFY_ASSETS_API_KEY"
	defaultAssetsMethod    = "GET"
	defaultAssetsQueryData = "query=%s"
)

var (
	//Set value for testing locally
	envAPIKey      = ""
	envAPIKeyExist = false
	//Set value for testing locally
	envAPIInvokeUrl      = ""
	envAPIInvokeUrlExist = false
)

type Target struct {
	Name     string `json:"domainName,omitempty"`
	UUID     string `json:"domainUUID,omitempty"`
	Owner    string `json:"teamName,omitempty"`
	OwnerKey string `json:"detectifyApiKey,omitempty"`
}
