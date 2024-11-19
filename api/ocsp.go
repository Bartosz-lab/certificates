package api

import (
	"io"
	"net/http"

	"github.com/smallstep/certificates/api/render"
	"github.com/smallstep/certificates/errs"
)

func OCSP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Content-Type") != "application/ocsp-request" {
		render.Error(w, r, errs.New(http.StatusUnsupportedMediaType, "unsupported media type"))
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		render.Error(w, r, errs.Wrap(http.StatusInternalServerError, err, "failed to read request body"))
		return
	}
	defer r.Body.Close()

	ocspResp, err := mustAuthority(r.Context()).GetOCSPResponse(body)
	if err != nil {
		render.Error(w, r, err)
		return
	}

	w.Header().Set("Content-Type", "application/ocsp-response")
	w.Write(ocspResp)
}
