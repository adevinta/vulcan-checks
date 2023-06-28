package utils

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
)

func EnableDebug(enableFlag bool) {
	debugHTTPTraffic = enableFlag

}
func debug(data []byte, err error) {
	if err == nil {
		PrintLogs(fmt.Sprintf("[*] HTTP Traffic Debug:  %s\n\n", data))
	} else {
		PrintLogs(fmt.Sprintf("[!] HTTP Traffic Error: %s\n\n", err))
	}
}

/*
	Perform API communication with Detectify WebService

Example:

	performHTTPRequest(client, "GET", assetsURL, teamKey)
*/

func PerformHTTPRequest(client *http.Client, httpMethod, apiURL string, message string, myHeaders map[string]string) ([]byte, error) {
	bodyData := bytes.NewReader([]byte(message))

	req, err := http.NewRequest(httpMethod, apiURL, bodyData)

	if err != nil {
		return nil, CustomErrors(fmt.Sprintf("[PerformHTTPRequest] HTTP request error %s", err.Error()), 600)
	}

	for index, value := range myHeaders {
		req.Header.Add(index, value)
	}

	/*
	 Debug HTTP Request Traffic
	*/

	if debugHTTPTraffic {
		debug(httputil.DumpRequestOut(req, true))
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, CustomErrors(fmt.Sprintf("[PerformHTTPRequest] HTTP request error %v", err), 601)
	}
	defer resp.Body.Close()

	// Read response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, CustomErrors(fmt.Sprintf("[PerformHTTPRequest] HTTP response read error %v", err), 700)

	}

	return body, nil
}
