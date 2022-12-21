package main

import (
	"context"
	"fmt"

	"github.com/adevinta/vulcan-check-sdk/helpers/command"
	"github.com/sirupsen/logrus"
)

const Cmd = `gosec`

// NOTE: keep this const block separated to not mess with the iota generated
// values.
var RuleIdMap = map[string]string{
	"G101": "Look for hardcoded credentials",
	"G102": "Bind to all interfaces",
	"G103": "Audit the use of unsafe block",
	"G104": "Audit errors not checked",
	"G106": "Audit the use of ssh.InsecureIgnoreHostKey function",
	"G107": "Url provided to HTTP request as taint input",
	"G108": "Profiling endpoint is automatically exposed",
	"G109": "Converting strconv.Atoi result to int32/int16",
	"G110": "Detect io.Copy instead of io.CopyN when decompression",
	"G111": "Detect http.Dir('/') as a potential risk",
	"G112": "Detect ReadHeaderTimeout not configured as a potential risk",
	"G113": "Usage of Rat.SetString in math/big with an overflow",
	"G114": "Use of net/http serve function that has no support for setting timeouts",
	"G201": "SQL query construction using format string",
	"G202": "SQL query construction using string concatenation",
	"G203": "Use of unescaped data in HTML templates",
	"G204": "Audit use of command execution",
	"G301": "Poor file permissions used when creating a directory",
	"G302": "Poor file permissions used when creation file or using chmod",
	"G303": "Creating tempfile using a predictable path",
	"G304": "File path provided as taint input",
	"G305": "File path traversal when extracting zip archive",
	"G306": "Poor file permissions used when writing to a file",
	"G307": "Unsafe defer call of a method returning an error",
	"G401": "Detect the usage of DES, RC4, MD5 or SHA1",
	"G402": "Look for bad TLS connection settings",
	"G403": "Ensure minimum RSA key length of 2048 bits",
	"G404": "Insecure random number source (rand)",
	"G501": "Import blocklist: crypto/md5",
	"G502": "Import blocklist: crypto/des",
	"G503": "Import blocklist: crypto/rc4",
	"G504": "Import blocklist: net/http/cgi",
	"G505": "Import blocklist: crypto/sha1",
	"G601": "Implicit memory aliasing in RangeStmt",
}

const (
	GosecStatusOK = iota // This should be always 0.
	GosecStatusOKwithIssues
)

var params = []string{"-fmt=json"}
var AlwaysExcluded = []string{".*swagger.*.js"}

// GosecOutput and Result represent the output information from the gosec
// command.  Non-used fields have been intentionally ommitted.

type GosecOutput struct {
	GolangErrors struct {
	} `json:"Golang errors"`
	Issues []Issue `json:"Issues"`
	Stats  struct {
		Files int `json:"files"`
		Lines int `json:"lines"`
		Nosec int `json:"nosec"`
		Found int `json:"found"`
	} `json:"Stats"`
	GosecVersion string `json:"GosecVersion"`
}
type Issue struct {
	Severity   string `json:"severity"`
	Confidence string `json:"confidence"`
	Cwe        struct {
		ID  string `json:"id"`
		URL string `json:"url"`
	} `json:"cwe"`
	RuleID       string      `json:"rule_id"`
	Details      string      `json:"details"`
	File         string      `json:"file"`
	Code         string      `json:"code"`
	Line         string      `json:"line"`
	Column       string      `json:"column"`
	Nosec        bool        `json:"nosec"`
	Suppressions interface{} `json:"suppressions"`
}

func runGosec(ctx context.Context, logger *logrus.Entry, timeout int, exclude []string, ruleset, dir string) (*GosecOutput, error) {
	exclusions := exclude
	for _, e := range exclusions {
		params = append(params, "-exclude-dir", e)
	}
	params = append(params, "-exclude=G101")
	params = append(params, fmt.Sprintf("%s/...", dir))

	var report GosecOutput
	exitCode, err := command.ExecuteAndParseJSON(ctx, logger, &report, Cmd, params...)
	logger.WithFields(logrus.Fields{"error": err}).Info("error")
	if err != nil {
		return nil, err
	}

	logger.WithFields(logrus.Fields{"exit_code": exitCode, "report": report}).Debug("gosec command finished")

	switch exitCode {
	case GosecStatusOK, GosecStatusOKwithIssues:
		return &report, nil
	default:
		err := fmt.Errorf("gosec scan failed with exit code %d", exitCode)
		logger.WithError(err).WithFields(logrus.Fields{"errors": report.GolangErrors}).Error("")
		return nil, err
	}
}
