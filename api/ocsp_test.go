package api

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ocsp"
)

func Test_OCSP(t *testing.T) {

	type test struct {
		contentType  string
		ocspResponse []byte
		statusCode   int
	}

	tests := map[string]test{
		"wrong-content-type": {
			contentType: "application/json",
			statusCode:  http.StatusUnsupportedMediaType,
		},
		"ok": {
			contentType:  "application/ocsp-request",
			statusCode:   http.StatusOK,
			ocspResponse: ocsp.MalformedRequestErrorResponse,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			mockMustAuthority(t, &mockAuthority{ret1: tt.ocspResponse})

			chiCtx := chi.NewRouteContext()
			req := httptest.NewRequest("POST", "http://example.com/ocsp", http.NoBody)
			req.Header.Set("Content-Type", tt.contentType)
			req = req.WithContext(context.WithValue(context.Background(), chi.RouteCtxKey, chiCtx))
			w := httptest.NewRecorder()
			OCSP(w, req)

			res := w.Result()

			assert.Equal(t, tt.statusCode, res.StatusCode)

			if tt.ocspResponse != nil {
				body, err := io.ReadAll(res.Body)
				res.Body.Close()
				assert.NoError(t, err)

				assert.Equal(t, tt.ocspResponse, body)
			}
		})
	}
}
