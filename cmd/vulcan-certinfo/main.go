/*
Copyright 2019 Adevinta
*/

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	check "github.com/adevinta/vulcan-check-sdk"
	"github.com/adevinta/vulcan-check-sdk/helpers"
	checkstate "github.com/adevinta/vulcan-check-sdk/state"
	report "github.com/adevinta/vulcan-report"
)

type certificateChecker struct {
	ownerCertificate *x509.Certificate
	certificateInfo  []report.Vulnerability
	expired          bool
	fingerprint      string
	notes            string
	data             []byte
}

var (
	checkName              = "vulcan-certinfo"
	logger                 = check.NewCheckLog(checkName)
	defaultTimeout         = 2
	defaultTLSPort         = 443
	defaultExpiricyWarning = 30
	defaultExpiricyError   = 15
)

type options struct {
	Timeout           int `json:"timeout"`          // Timeout parameter.
	Port              int `json:"port"`             // Port to check for SSL certificate.
	ExpiritionWarning int `json:"expiricy_warning"` // Certificate expiration warning period.
	ExpiritionError   int `json:"expiricy_error"`   // Certificate expiration error period.
}

func (checker *certificateChecker) getOwnerCertificate(target string, port int, timeout int, skipVerify bool) error {
	host := fmt.Sprintf("%s:%d", target, port)

	cfg := tls.Config{
		InsecureSkipVerify: skipVerify,
	}

	dialer := &net.Dialer{
		Timeout: time.Duration(timeout) * time.Second,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", host, &cfg)
	// Handle certificate errors.
	if err != nil {
		// Don't fail the check if the target can not be accessed.
		if _, ok := err.(*net.OpError); ok {
			return nil
		}

		if strings.HasPrefix(err.Error(), "x509: certificate has expired or is not yet valid") {
			checker.certificateInfo = append(checker.certificateInfo, expiredCertificate)
			checker.expired = true
			return nil
		}

		if strings.HasPrefix(err.Error(), "x509: certificate is valid for") {
			checker.certificateInfo = append(checker.certificateInfo, certificateHostMismatch)
			checker.expired = true
			return nil
		}

		if err.Error() == "x509: certificate signed by unknown authority" {
			checker.certificateInfo = append(checker.certificateInfo, certificateAuthorityUntrusted)
			return nil
		}

		return err
	}
	defer conn.Close()

	if len(conn.ConnectionState().PeerCertificates) == 0 {
		return errors.New("No certificate obtained from host")
	}

	checker.ownerCertificate = conn.ConnectionState().PeerCertificates[0]

	return nil
}

func (checker *certificateChecker) extractCertificateInfo() error {
	if checker.ownerCertificate == nil {
		return nil
	}

	buf := bytes.NewBufferString("")

	buf.WriteString(fmt.Sprintf("SignatureAlgorithm: %s\n", checker.ownerCertificate.SignatureAlgorithm))
	buf.WriteString(fmt.Sprintf("Version: %d\n", checker.ownerCertificate.Version))

	buf.WriteString(fmt.Sprintf("Issuer.Country: %s\n", strings.Join(checker.ownerCertificate.Issuer.Country, " ")))
	buf.WriteString(fmt.Sprintf("Issuer.Organization: %s\n", strings.Join(checker.ownerCertificate.Issuer.Organization, " ")))
	buf.WriteString(fmt.Sprintf("Issuer.OrganizationalUnit: %s\n", strings.Join(checker.ownerCertificate.Issuer.OrganizationalUnit, " ")))
	buf.WriteString(fmt.Sprintf("Issuer.CommonName: %s\n", checker.ownerCertificate.Issuer.CommonName))
	buf.WriteString(fmt.Sprintf("Issuer.Locality: %s\n", strings.Join(checker.ownerCertificate.Subject.Locality, " ")))
	buf.WriteString(fmt.Sprintf("Issuer.CommonName: %s\n", checker.ownerCertificate.Subject.CommonName))

	buf.WriteString(fmt.Sprintf("Subject.Country: %s\n", strings.Join(checker.ownerCertificate.Subject.Country, " ")))
	buf.WriteString(fmt.Sprintf("Subject.Organization: %s\n", strings.Join(checker.ownerCertificate.Subject.Organization, " ")))
	buf.WriteString(fmt.Sprintf("Subject.OrganizationalUnit: %s\n", strings.Join(checker.ownerCertificate.Subject.OrganizationalUnit, " ")))
	buf.WriteString(fmt.Sprintf("Subject.CommonName: %s\n", checker.ownerCertificate.Subject.CommonName))
	buf.WriteString(fmt.Sprintf("Subject.Locality: %s\n", strings.Join(checker.ownerCertificate.Subject.Locality, " ")))
	buf.WriteString(fmt.Sprintf("Subject.CommonName: %s\n", checker.ownerCertificate.Subject.CommonName))

	buf.WriteString(fmt.Sprintf("NotBefore: %s\n", checker.ownerCertificate.NotBefore))
	buf.WriteString(fmt.Sprintf("NotAfter: %s\n", checker.ownerCertificate.NotAfter))

	buf.WriteString(fmt.Sprintf("NotBefore(timestamp): %d\n", checker.ownerCertificate.NotBefore.Unix()))
	buf.WriteString(fmt.Sprintf("NotAfter(timestamp): %d\n", checker.ownerCertificate.NotAfter.Unix()))

	buf.WriteString(fmt.Sprintf("DNSNames: %s\n", strings.Join(checker.ownerCertificate.DNSNames, " ")))

	// The fingerprint is the hash (sha256) of the whole raw certificate.
	s := sha256.New()
	_, err := s.Write(checker.ownerCertificate.Raw)
	if err != nil {
		return err
	}
	sha256Fingerprint := strings.ToUpper(hex.EncodeToString(s.Sum(nil)))
	buf.WriteString(fmt.Sprintf("SHA-256 Fingerprint: %s\n", sha256Fingerprint))
	checker.fingerprint = sha256Fingerprint

	checker.notes = buf.String()
	checker.data = checker.ownerCertificate.Raw

	daysUntilExpiration := int(time.Until(checker.ownerCertificate.NotAfter).Hours() / 24)

	// Check certificate expiration.
	if !checker.expired && daysUntilExpiration < defaultExpiricyError {
		criticalCertificateExpiration.Details = fmt.Sprintf("The certificate will expire in %v days.", daysUntilExpiration)
		checker.certificateInfo = append(checker.certificateInfo, criticalCertificateExpiration)
	} else if !checker.expired && daysUntilExpiration < defaultExpiricyWarning {
		warningCertificateExpiration.Details = fmt.Sprintf("The certificate will expire in %v days.", daysUntilExpiration)
		checker.certificateInfo = append(checker.certificateInfo, warningCertificateExpiration)
	}

	// Can't check if certificate is revoked:
	// https://github.com/golang/go/issues/18323
	return nil
}

func main() {
	run := func(ctx context.Context, target, assetType, optJSON string, state checkstate.State) (err error) {
		var opt options
		logger.Printf("Starting the %v check", checkName)

		if target == "" {
			return errors.New("No target hostname provided")
		}

		if optJSON != "" {
			if err = json.Unmarshal([]byte(optJSON), &opt); err != nil {
				return err
			}
		}

		isReachable, err := helpers.IsReachable(target, assetType, nil)
		if err != nil {
			logger.Warnf("Can not check asset reachability: %v", err)
		}
		if !isReachable {
			return checkstate.ErrAssetUnreachable
		}

		if opt.Timeout == 0 {
			opt.Timeout = defaultTimeout
		}

		if opt.Port == 0 {
			opt.Port = defaultTLSPort
		}

		if opt.ExpiritionWarning == 0 {
			opt.ExpiritionWarning = defaultExpiricyWarning
		}

		if opt.ExpiritionError == 0 {
			opt.ExpiritionError = defaultExpiricyError
		}

		checker := certificateChecker{}
		err = checker.getOwnerCertificate(target, opt.Port, opt.Timeout, false)
		if err != nil {
			return err
		}

		// Try again with (SkipVerify == true).
		if checker.ownerCertificate == nil {
			err = checker.getOwnerCertificate(target, opt.Port, opt.Timeout, true)
			if err != nil {
				return err
			}
		}

		err = checker.extractCertificateInfo()
		if err != nil {
			return err
		}

		for _, certInfo := range checker.certificateInfo {
			certInfo.AffectedResource = fmt.Sprintf("%s:%d", checker.fingerprint, opt.Port)
			certInfo.AffectedResourceString = fmt.Sprintf("%d/tcp", opt.Port)
			certInfo.Fingerprint = helpers.ComputeFingerprint()
			state.AddVulnerabilities(certInfo)
		}

		if checker.ownerCertificate != nil {
			state.Notes = checker.notes
			state.Data = checker.data
		}

		return nil
	}
	c := check.NewCheckFromHandler(checkName, run)

	c.RunAndServe()
}
