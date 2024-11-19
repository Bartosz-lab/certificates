package authority

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/pkg/errors"
	"github.com/smallstep/certificates/errs"
	"github.com/smallstep/nosql/database"
	"golang.org/x/crypto/ocsp"
)

func (a *Authority) GetOCSPResponse(request []byte) ([]byte, error) {
	fatal := func(err error) ([]byte, error) {
		return nil, errs.Wrap(http.StatusInternalServerError, err, "authority.GetOCSPResponse")
	}
	fatalOCSP := func(err error) ([]byte, error) {
		log.Print("OCSP error: ", err)
		return ocsp.InternalErrorErrorResponse, nil
	}

	if !a.config.OCSP.IsEnabled() {
		fatal(errors.New("OCSP server is not enabled"))
	}

	ocspReq, err := ocsp.ParseRequest(request)
	if err != nil {
		return ocsp.MalformedRequestErrorResponse, nil
	}

	now := time.Now()
	sn := ocspReq.SerialNumber.String()
	respTemplate := ocsp.Response{
		SerialNumber: ocspReq.SerialNumber,
		ThisUpdate:   now,
		NextUpdate:   time.Now().Add(time.Hour),
		Certificate:  a.ocspCert,
	}

	cert, err := a.db.GetCertificate(sn)
	if err != nil && !database.IsErrNotFound(err) {
		fatalOCSP(err)
	} else if cert == nil {
		respTemplate.Status = ocsp.Unknown
	} else {
		rci, err := a.db.GetRevokedCertificateInfo(sn)
		if err != nil {
			fatalOCSP(err)
		}

		if rci != nil {
			respTemplate.Status = ocsp.Revoked
			respTemplate.RevocationReason = rci.ReasonCode
			fmt.Println("reason code: ", rci.ReasonCode)
			respTemplate.RevokedAt = rci.RevokedAt
		} else {
			respTemplate.Status = ocsp.Good
		}
	}

	respBytes, err := ocsp.CreateResponse(a.GetIntermediateCertificate(), a.ocspCert, respTemplate, *a.ocspSigner)
	if err != nil {
		fatalOCSP(err)
	}

	return respBytes, nil
}

// GetOCSPSigningCertificate creates a new certificate to be used for signing OCSP responses.
func (a *Authority) GetOCSPSigningCertificate() (*x509.Certificate, *crypto.Signer, error) {
	fatal := func(err error) (*x509.Certificate, *crypto.Signer, error) {
		return nil, nil, errs.Wrap(http.StatusInternalServerError, err, "authority.GetOCSPSigningCertificate")
	}

	resp, _, signer, err := a.GetCertificate(a.config.OCSP.CommonName, nil, []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning})
	if err != nil {
		return fatal(err)
	}

	return resp.Certificate, signer, nil
}

func (a *Authority) initOCSP() error {
	fatal := func(err error) error {
		return errs.Wrap(http.StatusInternalServerError, err, "authority.InitOCSP")
	}

	if !a.config.OCSP.IsEnabled() {
		return nil
	}
	log.Printf("Initiating OCSP responder")

	var err error
	a.ocspCert, a.ocspSigner, err = a.GetOCSPSigningCertificate()
	if err != nil {
		return fatal(err)
	}

	// TODO: add refresher for OCSP certificate

	return nil
}
