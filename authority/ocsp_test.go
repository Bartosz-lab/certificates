package authority

import (
	"crypto"
	"crypto/x509"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/smallstep/assert"
	"github.com/smallstep/certificates/authority/config"
	"github.com/smallstep/certificates/db"
	"go.step.sm/crypto/pemutil"
	"golang.org/x/crypto/ocsp"
)

func TestAuthority_GetOCSPResponse(t *testing.T) {
	fooCrt, err := pemutil.ReadCertificate("testdata/certs/foo.crt")
	fooCrt.NotAfter = time.Now().Add(time.Hour)
	assert.FatalError(t, err)

	intermediateCrt, err := pemutil.ReadCertificate("testdata/certs/intermediate_ca.crt")
	intermediateCrt.NotAfter = time.Now().AddDate(1, 0, 0)
	assert.FatalError(t, err)

	validReq, err := ocsp.CreateRequest(fooCrt, intermediateCrt, &ocsp.RequestOptions{})
	assert.FatalError(t, err)

	type test struct {
		auth           *Authority
		request        []byte
		expected       []byte        // used for nonsuccessful responses
		expectedStruct ocsp.Response // used for successful responses
		err            error
	}

	tests := map[string]func() test{
		"fail/ocsp-not-enabled": func() test {
			a := testAuthority(t)
			a.config.OCSP = &config.OCSPConfig{
				Enabled: false,
			}

			return test{
				auth:    a,
				request: []byte("request"),
				err:     errors.New("authority.GetOCSPResponse: OCSP server is not enabled"),
			}
		},
		"fail/parse-request-error": func() test {
			a := testAuthority(t)
			a.config.OCSP = &config.OCSPConfig{
				Enabled: true,
			}

			return test{
				auth:     a,
				request:  []byte("request"),
				expected: ocsp.MalformedRequestErrorResponse,
			}
		},
		"fail/get-certificate-error": func() test {
			a := testAuthority(t, WithDatabase(&db.MockAuthDB{
				MGetCertificate: func(sn string) (*x509.Certificate, error) {
					return nil, errors.New("unknown error")
				},
			}))
			a.config.OCSP = &config.OCSPConfig{
				Enabled: true,
			}

			return test{
				auth:     a,
				request:  validReq,
				expected: ocsp.InternalErrorErrorResponse,
			}
		},
		"ok/unknown-certificate": func() test {
			a := testAuthority(t, WithDatabase(&db.MockAuthDB{
				MGetCertificate: func(sn string) (*x509.Certificate, error) {
					return nil, nil
				},
			}))
			a.config.OCSP = &config.OCSPConfig{
				Enabled: true,
			}

			signer, err := a.GetX509Signer()
			assert.FatalError(t, err)

			a.ocspSigner = &signer
			a.ocspCert = intermediateCrt

			return test{
				auth:    a,
				request: validReq,
				expectedStruct: ocsp.Response{
					Status:       ocsp.Unknown,
					SerialNumber: fooCrt.SerialNumber,
				},
			}
		},
		"fail/get-revoked-certificate-info-error": func() test {
			a := testAuthority(t, WithDatabase(&db.MockAuthDB{
				MGetCertificate: func(sn string) (*x509.Certificate, error) {
					return fooCrt, nil
				},
				MGetRevokedCertificateInfo: func(sn string) (*db.RevokedCertificateInfo, error) {
					return nil, errors.New("unknown error")
				},
			}))
			a.config.OCSP = &config.OCSPConfig{
				Enabled: true,
			}

			return test{
				auth:     a,
				request:  validReq,
				expected: ocsp.InternalErrorErrorResponse,
			}
		},
		"ok/good-status": func() test {
			a := testAuthority(t, WithDatabase(&db.MockAuthDB{
				MGetCertificate: func(sn string) (*x509.Certificate, error) {
					return fooCrt, nil
				},
				MGetRevokedCertificateInfo: func(sn string) (*db.RevokedCertificateInfo, error) {
					return nil, nil
				},
			}))
			a.config.OCSP = &config.OCSPConfig{
				Enabled: true,
			}

			signer, err := a.GetX509Signer()
			assert.FatalError(t, err)

			a.ocspSigner = &signer
			a.ocspCert = intermediateCrt

			return test{
				auth:    a,
				request: validReq,
				expectedStruct: ocsp.Response{
					Status:       ocsp.Good,
					SerialNumber: fooCrt.SerialNumber,
				},
			}
		},
		"ok/revoked-status": func() test {
			revocationTime := time.Now().Add(-time.Hour)
			a := testAuthority(t, WithDatabase(&db.MockAuthDB{
				MGetCertificate: func(sn string) (*x509.Certificate, error) {
					return fooCrt, nil
				},
				MGetRevokedCertificateInfo: func(sn string) (*db.RevokedCertificateInfo, error) {
					return &db.RevokedCertificateInfo{
						Serial:     sn,
						ReasonCode: 2,
						RevokedAt:  revocationTime,
					}, nil
				},
			}))
			a.config.OCSP = &config.OCSPConfig{
				Enabled: true,
			}

			signer, err := a.GetX509Signer()
			assert.FatalError(t, err)

			a.ocspSigner = &signer
			a.ocspCert = intermediateCrt

			return test{
				auth:    a,
				request: validReq,
				expectedStruct: ocsp.Response{
					Status:           ocsp.Revoked,
					SerialNumber:     fooCrt.SerialNumber,
					RevocationReason: 2,
					RevokedAt:        revocationTime.UTC().Truncate(time.Second),
				},
			}
		},

		"ok/ocsp-signing-certificate-error": func() test {
			// This test will fail because the signer is not set

			a := testAuthority(t)
			a.config.OCSP = &config.OCSPConfig{
				Enabled: true,
			}

			return test{
				auth:     a,
				request:  validReq,
				expected: ocsp.InternalErrorErrorResponse,
			}
		},
	}

	for name, f := range tests {
		tc := f()
		t.Run(name, func(t *testing.T) {
			ocspResp, err := tc.auth.GetOCSPResponse(tc.request)
			if tc.err != nil {
				assert.Error(t, err, tc.err.Error())
				assert.Nil(t, ocspResp)
				return
			}

			assert.FatalError(t, err)
			assert.NotNil(t, ocspResp)
			if tc.expected != nil {
				assert.Equals(t, ocspResp, tc.expected)
			} else {
				parsedResp, err := ocsp.ParseResponse(ocspResp, nil)
				assert.FatalError(t, err)

				assert.Equals(t, parsedResp.Status, tc.expectedStruct.Status)
				assert.Equals(t, parsedResp.SerialNumber, tc.expectedStruct.SerialNumber)
				assert.Equals(t, parsedResp.RevocationReason, tc.expectedStruct.RevocationReason)
				assert.Equals(t, parsedResp.RevokedAt, tc.expectedStruct.RevokedAt)
			}
		})
	}
}

func TestNewEmbedded_GetOCSPSigningCertificate(t *testing.T) {
	caPEM, err := os.ReadFile("testdata/certs/root_ca.crt")
	assert.FatalError(t, err)

	crt, err := pemutil.ReadCertificate("testdata/certs/intermediate_ca.crt")
	assert.FatalError(t, err)
	key, err := pemutil.Read("testdata/secrets/intermediate_ca_key", pemutil.WithPassword([]byte("pass")))
	assert.FatalError(t, err)

	a, err := NewEmbedded(WithX509RootBundle(caPEM), WithX509Signer(crt, key.(crypto.Signer)))
	a.config.OCSP = &config.OCSPConfig{
		Enabled:    true,
		CommonName: "ocsp smallstep test",
	}
	assert.FatalError(t, err)

	// GetOCSPSigningCertificate
	retCrt, retSigner, err := a.GetOCSPSigningCertificate()
	assert.FatalError(t, err)

	assert.Equals(t, retCrt.Subject.CommonName, a.config.OCSP.CommonName)
	assert.Equals(t, retCrt.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageOCSPSigning})
	assert.NotNil(t, retSigner)
}
