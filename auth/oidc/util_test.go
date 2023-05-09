//nolint
package oidc

import (
	"encoding/base64"
	"github.com/gin-gonic/gin"
	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/stretchr/testify/assert"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestSecureKey(t *testing.T) {
	key, err := generateSecureKey(1)
	assert.NoError(t, err)
	buf, err := base64.RawURLEncoding.DecodeString(key)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(buf))

	key, err = generateSecureKey(9)
	assert.NoError(t, err)
	buf, err = base64.RawURLEncoding.DecodeString(key)
	assert.NoError(t, err)
	assert.Equal(t, 2, len(buf))
}

func TestParseJWT_Success(t *testing.T) {
	signingKey := &jose.SigningKey{Algorithm: jose.HS256, Key: []byte("my-secure-key")}
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.RPckld04bZdohex0AS9F8SAJgO3nw6A-HNFjNbT2N28"

	claims := new(jwt.Claims)
	err := parseJWT(token, signingKey, claims)
	assert.NoError(t, err)
}

func TestParseJWT_InvalidSignature(t *testing.T) {
	signingKey := &jose.SigningKey{Algorithm: jose.HS256, Key: []byte("my-secure-key")}
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.RPckld04bZdOhex0AS9F8SAJgO3nw6A-HNFjNbT2N28"

	claims := new(jwt.Claims)
	err := parseJWT(token, signingKey, claims)
	assert.Error(t, err)
	assert.Equal(t, "failed to validate JWT: go-jose/go-jose: error in cryptographic primitive", err.Error())
}

func TestParseJWT_InvalidKey(t *testing.T) {
	signingKey := &jose.SigningKey{Algorithm: jose.HS256, Key: []byte("invalid-key")}
	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.RPckld04bZdohex0AS9F8SAJgO3nw6A-HNFjNbT2N28"

	claims := new(jwt.Claims)
	err := parseJWT(token, signingKey, claims)
	assert.Error(t, err)
	assert.Equal(t, "failed to validate JWT: go-jose/go-jose: error in cryptographic primitive", err.Error())
}

func TestParseJWT_IncorrectAlgorithm(t *testing.T) {
	signingKey := &jose.SigningKey{Algorithm: jose.HS256, Key: []byte("my-secure-key")}
	// Has a wrong algorithm in header and signature
	token := "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.JZfcEryx7E7x4fReKbo9FNfCmXY4nXO2MeGNIDdsukoRtmzyFDq9ULjwe7oS3UB8YtjCis3bofGz0vXGHUIJPA"

	claims := new(jwt.Claims)
	err := parseJWT(token, signingKey, claims)
	assert.Error(t, err)
	assert.Equal(t, "algorithm validation failed", err.Error())
}

func TestParseJWT_ParsingFailed(t *testing.T) {
	signingKey := &jose.SigningKey{Algorithm: jose.HS256, Key: []byte("my-secure-key")}
	token := "eyJhbGciOiJIUzI1NiInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.RPckld04bZdohex0AS9F8SAJgO3nw6A-HNFjNbT2N28"

	claims := new(jwt.Claims)
	err := parseJWT(token, signingKey, claims)
	assert.Error(t, err)
	assert.Equal(t, "failed to parse JWT: invalid character '\\'' after object key:value pair", err.Error())
}

func TestRedirectFromCookie(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	ctx.Request = &http.Request{URL: &url.URL{}}

	s := &state{}
	s.redirect(ctx, "http://www.example.com")
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "http://www.example.com", rec.Header().Get("Location"))

	rec = httptest.NewRecorder()
	ctx, _ = gin.CreateTestContext(rec)
	ctx.Request = &http.Request{URL: &url.URL{}}
	s = &state{Redirect: "http://www.example2.com"}
	s.redirect(ctx, "http://www.example.com")
	assert.Equal(t, http.StatusOK, rec.Code) // Why OK???
	assert.Equal(t, "http://www.example2.com", rec.Header().Get("Location"))

	rec = httptest.NewRecorder()
	ctx, _ = gin.CreateTestContext(rec)
	ctx.Request = &http.Request{URL: &url.URL{}}
	s = &state{Data: "value"}
	s.redirect(ctx, "http://www.example.com")
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "{\"data\":\"value\"}", rec.Body.String())
}
