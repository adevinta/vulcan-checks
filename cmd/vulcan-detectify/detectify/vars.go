package detectify

import (
	"net/http"

	check "github.com/adevinta/vulcan-check-sdk"
	checkstate "github.com/adevinta/vulcan-check-sdk/state"
	report "github.com/adevinta/vulcan-report"
)

const (
	contentType     = "application/json"
	userAgent       = "vulcan-detectify-client/1.1"
	defaultPageSize = 100
	BaseURL         = "https://api.detectify.com/rest/v2"
	checkName       = "vulcan-detectify"
)

var (
	logger            = check.NewCheckLog(checkName)
	defaultVulnStatus = [...]string{"active", "new"} // The value can be `active`, `new`, `patched`, `regression`, `accepted_risk`, or `false_positive`.

)

type detectifyCheckAgent struct {
	client                                                              *http.Client
	state                                                               *checkstate.State
	detectifyVulns                                                      map[string]report.Vulnerability
	vulnStatus                                                          []string
	teamName, teamKey, vulcanTarget, domainName, assetToken, pageMarker string
	pageSize                                                            int
}

type Target struct {
	Name     string `json:"domainName,omitempty"`
	UUID     string `json:"domainUUID,omitempty"`
	Owner    string `json:"teamName,omitempty"`
	OwnerKey string `json:"detectifyApiKey,omitempty"`
}

// SubDomains represents the response from the /assets/{assetToken}/subdomains/ endpoint
type SubDomains struct {
	Assets []struct {
		AddedBy    []string `json:"added_by"`
		Created    string   `json:"created"`
		Discovered string   `json:"discovered"`
		LastSeen   string   `json:"last_seen"`
		Monitored  bool     `json:"monitored"`
		Name       string   `json:"name"`
		Status     string   `json:"status"`
		Token      string   `json:"token"`
		Updated    string   `json:"updated"`
	} `json:"assets"`
	CurrentMarker string `json:"current_marker"`
	HasMore       bool   `json:"has_more"`
	NextMarker    string `json:"next_marker"`
}

// Vulnerabilities List
type VulnerabilityPage struct {
	Vulnerabilities      []Vulnerability `json:"vulnerabilities"`
	TotalVulnerabilities int             `json:"total_vulnerabilities"`
	CurrentMarker        string          `json:"current_marker"`
	NextMarker           string          `json:"next_marker"`
	HasMore              bool            `json:"has_more"`
}

// Vulnerability is a struct representing the information about a vulnerability
type Vulnerability struct {
	Host     string `json:"host"`
	VulnUUID string `json:"uuid"`
	Asset    struct {
		Name  string `json:"name"`
		Token string `json:"token"`
	} `json:"asset"`
	AssetToken string `json:"asset_token"`
	Cookie     struct {
		Domain   string `json:"domain"`
		Expires  string `json:"expires"`
		HttpOnly bool   `json:"httponly"`
		Name     string `json:"name"`
		Path     string `json:"path"`
		Secure   bool   `json:"secure"`
		Value    string `json:"value"`
	} `json:"cookie"`
	CreatedAt  string `json:"created_at"`
	CVSSScores struct {
		CVSS20 struct {
			Score    float64 `json:"score"`
			Severity string  `json:"severity"`
			Vector   string  `json:"vector"`
		} `json:"cvss_2_0"`
		CVSS30 struct {
			Score    float64 `json:"score"`
			Severity string  `json:"severity"`
			Vector   string  `json:"vector"`
		} `json:"cvss_3_0"`
		CVSS31 struct {
			Score    float64 `json:"score"`
			Severity string  `json:"severity"`
			Vector   string  `json:"vector"`
		} `json:"cvss_3_1"`
	} `json:"cvss_scores"`
	Definition struct {
		Description    string `json:"description"`
		IsCrowdsourced bool   `json:"is_crowdsourced"`
		ModuleRelease  string `json:"module_release"`
		ModuleVersion  string `json:"module_version"`
		Risk           string `json:"risk"`
		Title          string `json:"title"`
	} `json:"definition"`
	Details struct {
		Geography []struct {
			City        string `json:"city"`
			CountryCode string `json:"country_code"`
			CountryName string `json:"country_name"`
			Highlights  []struct {
				Field  string `json:"field"`
				Length int    `json:"length"`
				Offset int    `json:"offset"`
				Value  string `json:"value"`
			} `json:"highlights"`
			Latitude  string `json:"latitude"`
			Longitude string `json:"longitude"`
			Region    string `json:"region"`
			Topic     string `json:"topic"`
			Zip       string `json:"zip"`
		} `json:"geography"`
		Graph []struct {
			Data struct {
				Property1 []int `json:"property1"`
				Property2 []int `json:"property2"`
			} `json:"data"`
			Highlights []struct {
				Field  string `json:"field"`
				Length int    `json:"length"`
				Offset int    `json:"offset"`
				Value  string `json:"value"`
			} `json:"highlights"`
			Topic string `json:"topic"`
			Unit  string `json:"unit"`
		} `json:"graph"`
		HTML []struct {
			Highlights []struct {
				Field  string `json:"field"`
				Length int    `json:"length"`
				Offset int    `json:"offset"`
				Value  string `json:"value"`
			} `json:"highlights"`
			Topic string `json:"topic"`
			Value string `json:"value"`
		} `json:"html"`
		Image []struct {
			Height     int `json:"height"`
			Highlights []struct {
				Field  string `json:"field"`
				Length int    `json:"length"`
				Offset int    `json:"offset"`
				Value  string `json:"value"`
			} `json:"highlights"`
			Link  string `json:"link"`
			Topic string `json:"topic"`
			Width int    `json:"width"`
		} `json:"image"`

		Markdown []struct {
			Fallback   string `json:"fallback"`
			Highlights []struct {
				Field  string `json:"field"`
				Length int    `json:"length"`
				Offset int    `json:"offset"`
				Value  string `json:"value"`
			} `json:"highlights"`
			Topic string `json:"topic"`
			Value string `json:"value"`
		} `json:"markdown"`
		Text []struct {
			Highlights []struct {
				Field  string `json:"field"`
				Length int    `json:"length"`
				Offset int    `json:"offset"`
				Value  string `json:"value"`
			} `json:"highlights"`
			Topic string `json:"topic"`
			Value string `json:"value"`
		} `json:"text"`
		Video []struct {
			Highlights []struct {
				Field  string `json:"field"`
				Length int    `json:"length"`
				Offset int    `json:"offset"`
				Value  string `json:"value"`
			} `json:"highlights"`
			Link  string `json:"link"`
			Topic string `json:"topic"`
		} `json:"video"`
	} `json:"details"`
	Links struct {
		DetailsPage string `json:"details_page"`
	} `json:"links"`
	Location string `json:"location"`
	Owasp    []struct {
		Classification string `json:"classification"`
		Year           int    `json:"year"`
	} `json:"owasp"`
	Request struct {
		Body    string `json:"body"`
		Headers []struct {
			Name  string `json:"name"`
			UUID  string `json:"uuid"`
			Value string `json:"value"`
		} `json:"headers"`
		Method string `json:"method"`
		URL    string `json:"url"`
	} `json:"request"`
	Response struct {
		Body    string `json:"body"`
		Headers []struct {
			Name  string `json:"name"`
			UUID  string `json:"uuid"`
			Value string `json:"value"`
		} `json:"headers"`
		StatusCode int `json:"status_code"`
	} `json:"response"`

	ScanProfileToken string `json:"scan_profile_token"`
	ScanSource       string `json:"scan_source"`
	Severity         string `json:"severity"`
	Source           struct {
		Value string `json:"value"`
	} `json:"source"`
	Status string `json:"status"`
	Tags   []struct {
		Name string `json:"name"`
		UUID string `json:"uuid"`
	} `json:"tags"`
	Title     string `json:"title"`
	UpdatedAt string `json:"updated_at"`
	Version   string `json:"version"`
}
