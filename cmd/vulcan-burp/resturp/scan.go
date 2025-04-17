package resturp

// ScanStatusGraphQL defines the info returned by the Burp API when querying the status
// of a scan.
type ScanStatusGraphQL struct {
	Data struct {
		Scan struct {
			ScanID string         `json:"id"`
			Status string         `json:"status"`
			Issues []IssueGraphql `json:"issues"`
		} `json:"scan"`
	} `json:"data"`
}

// GraphQLErrorResponse defines the Burp GrapQL API error response structure.
type GraphQLErrorResponse struct {
	Errors []struct {
		Message    string `json:"message"`
		Extensions struct {
			Code int `json:"code"`
		} `json:"extensions"`
	} `json:"errors"`
}

type GetSiteID struct {
	Data struct {
		SiteTree struct {
			Sites []struct {
				ID      string `json:"id"`
				ScopeV2 struct {
					StartURLs []string `json:"start_urls"`
				} ` json:"scope_v2"`
			} `json:"sites"`
		} `json:"site_tree"`
	} `json:"data"`
}

type CreateSite struct {
	Data struct {
		CreateSite struct {
			Site struct {
				ID string `json:"id"`
			} `json:"site"`
		} `json:"create_site"`
	} `json:"data"`
}

type CreateScan struct {
	Data struct {
		CreateScheduleItem struct {
			ScheduleItem struct {
				ID string `json:"id"`
			} `json:"schedule_item"`
		} `json:"create_schedule_item"`
	} `json:"data"`
}
