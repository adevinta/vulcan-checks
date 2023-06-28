package detectify

import (
	"net/http"

	checkstate "github.com/adevinta/vulcan-check-sdk/state"
	report "github.com/adevinta/vulcan-report"
)

func newDetectifyClientBuilder(state checkstate.State) *detectifyCheckAgent {
	detectifyClient := detectifyCheckAgent{client: &http.Client{}, state: &state, detectifyVulns: make(map[string]report.Vulnerability)}
	detectifyClient.setDefaultVulnStatus()
	return &detectifyClient
}

func (detectifyClient *detectifyCheckAgent) resetClientMetadata() {
	detectifyClient.pageMarker = ""
	detectifyClient.pageSize = 0

}

func (detectifyClient *detectifyCheckAgent) setDefaultVulnStatus() {
	detectifyClient.vulnStatus = make([]string, len(defaultVulnStatus))
	copy(detectifyClient.vulnStatus, defaultVulnStatus[:])
}
