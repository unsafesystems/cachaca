package oidc

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/zitadel/oidc/v2/pkg/oidc"

	"github.com/gobeam/stringy"
)

const (
	maxStateCookieAge   = 15 * 60 // 15 minutes
	MaxSessionKeyLength = 4096
	StateKeyBitLength   = 256
	SessionKeyBitLength = 512
	BitsPerByte         = 8
)

var (
	ErrSessionTokenTooLong       = errors.New("session token too long")
	ErrStateMismatch             = errors.New("state mismatch")
	ErrAlgorithmValidationFailed = errors.New("algorithm validation failed")
	ErrTokenHeaderMissing        = errors.New("token header missing")
)

func toSnakeCase(str string) string {
	s := stringy.New(str)

	return s.SnakeCase().ToLower()
}

func generateSecureKey(bitLength int) (string, error) {
	byteLength := (bitLength + (BitsPerByte - 1)) / BitsPerByte
	buf := make([]byte, byteLength)

	_, err := rand.Read(buf)
	if err != nil {
		return "", fmt.Errorf("random key generation failed: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func isHTTPS(ctx *gin.Context) bool {
	return ctx.Request.URL != nil && ctx.Request.URL.Scheme == "https"
}

type StateCookieClaims struct {
	Redirect        string `json:"redirect,omitempty"`
	ContinuationKey string `json:"continuationKey,omitempty"`
}

func stateCookieName(ctx *gin.Context) string {
	// __Host- prefix according to https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies for increased security
	cookieName := fmt.Sprintf("__Host-%s-%s", cookiePrefix, "state")
	if !isHTTPS(ctx) {
		cookieName = fmt.Sprintf("%s-%s", cookiePrefix, "state")
	}

	return cookieName
}

// setStateCookie sets a cookie with a random state parameter and returns the state parameter.
func setStateCookie(ctx *gin.Context, signer jose.Signer) (string, error) {
	// Using a 32 character cryptographically random "state" parameter in OAuth 2.0 is recommended to prevent CSRF
	// attacks, and most servers can handle URIs up to at least 8,000 bytes in length as per the HTTP specification,
	// so a 32 character state parameter should not cause a 414 Request-URI Too Long error.
	// https://github.com/OpenBanking-Brasil/specs-seguranca/issues/160#issuecomment-890304219 states 128 characters
	// must be supported so we should be good to go.
	state, err := generateSecureKey(StateKeyBitLength)
	if err != nil {
		return "", err
	}

	stdClaims := jwt.Claims{
		ID:        "state",
		Issuer:    "",
		Subject:   state,
		Audience:  []string{"state"},
		Expiry:    jwt.NewNumericDate(time.Now().Add(maxStateCookieAge * time.Second)),
		NotBefore: jwt.NewNumericDate(time.Now()),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
	}

	claims := StateCookieClaims{
		Redirect:        ctx.Query("redirect"),
		ContinuationKey: ctx.Query("continuation_key"),
	}

	token, err := generateJWT(signer, stdClaims, claims)
	if err != nil {
		return "", err
	}

	ctx.SetCookie(stateCookieName(ctx), token, maxStateCookieAge, "", "", isHTTPS(ctx), true)

	return state, nil
}

func validateStateCookie(ctx *gin.Context, signingKey *jose.SigningKey, state string) (*StateCookieClaims, error) {
	cookie, err := ctx.Cookie(stateCookieName(ctx))
	if err != nil {
		return nil, fmt.Errorf("state cookie missing: %w", err)
	}

	stdClaims := new(jwt.Claims)
	stateClaims := new(StateCookieClaims)

	err = parseJWT(cookie, signingKey, stdClaims, stateClaims)
	if err != nil {
		return nil, err
	}

	err = stdClaims.Validate(jwt.Expected{
		Time: time.Now(),
	})
	if err != nil {
		return nil, fmt.Errorf("state cookie invalid: %w", err)
	}

	if len(state) == 0 || stdClaims.Subject != state {
		return nil, ErrStateMismatch
	}

	return stateClaims, nil
}

func redirectFromStateCookie(ctx *gin.Context, stateClaims *StateCookieClaims, defaultRedirectURL string) {
	if stateClaims.Redirect != "" {
		ctx.Redirect(http.StatusFound, stateClaims.Redirect)

		return
	}

	// The continuation_key is intended to be used in e.g. a SPA or native client to continue the flow after the
	// redirect. There we don't want or need a redirect but instead can use any value from JSON.
	if stateClaims.ContinuationKey != "" {
		ctx.JSON(http.StatusOK, gin.H{
			"continuation_key": stateClaims.ContinuationKey,
		})

		return
	}

	scheme := "http"
	if isHTTPS(ctx) {
		scheme = "https"
	}

	redirectURL := fmt.Sprintf("%s://%s%s", scheme, ctx.Request.Host, defaultRedirectURL)
	ctx.Redirect(http.StatusFound, redirectURL)
}

func setSessionCookie(ctx *gin.Context, tokens *oidc.Tokens[*oidc.IDTokenClaims],
	signer jose.Signer, claims ...interface{},
) error {
	// The OWASP and NIST recommendations suggest that session keys should be at least 128 bits in length to resist
	// cryptographic attacks and provide an acceptable level of security. But 512 is also "only" 64 bytes...
	sessionKey, err := generateSecureKey(SessionKeyBitLength)
	if err != nil {
		return err
	}

	// Set the expiry to the expiry of the access token - or maximum of 1 hour - whatever is shorter
	expiry := time.Now().Add(time.Hour)
	if tokens.Token.Expiry.Before(expiry) {
		expiry = tokens.Token.Expiry
	}

	subject := ""
	if tokens.IDTokenClaims != nil {
		subject = tokens.IDTokenClaims.GetSubject()
	}

	builder := jwt.Signed(signer)
	builder = builder.Claims(jwt.Claims{
		ID:        sessionKey,
		Subject:   subject,
		Expiry:    jwt.NewNumericDate(expiry),
		NotBefore: jwt.NewNumericDate(time.Now()),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
	})

	for _, claim := range claims {
		builder = builder.Claims(claim)
	}

	token, err := builder.CompactSerialize()
	if err != nil {
		return fmt.Errorf("failed to generate session token: %w", err)
	}

	if len(token) >= MaxSessionKeyLength {
		return ErrSessionTokenTooLong
	}

	// __Host- prefix according to https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies for increased security
	cookieName := fmt.Sprintf("__Host-%s-session", cookiePrefix)
	if !isHTTPS(ctx) {
		cookieName = fmt.Sprintf("%s-session", cookiePrefix)
	}

	cookieExpiry := int(time.Until(expiry).Seconds())
	ctx.SetCookie(cookieName, token, cookieExpiry, "", "", isHTTPS(ctx), true)
	ctx.Header("Authorization", "Bearer "+token)

	return nil
}

func generateJWT(signer jose.Signer, claims ...interface{}) (string, error) {
	builder := jwt.Signed(signer)

	for _, claim := range claims {
		builder = builder.Claims(claim)
	}

	token, err := builder.CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("failed to generate JWT: %w", err)
	}

	return token, nil
}

func parseJWT(token string, key *jose.SigningKey, claims ...interface{}) error {
	tok, err := jwt.ParseSigned(token)
	if err != nil {
		return fmt.Errorf("failed to parse JWT: %w", err)
	}

	if len(tok.Headers) != 1 {
		return ErrTokenHeaderMissing
	}

	header := tok.Headers[0]
	if string(key.Algorithm) != header.Algorithm {
		return ErrAlgorithmValidationFailed
	}

	err = tok.Claims(key.Key, claims...)
	if err != nil {
		return fmt.Errorf("failed to validate JWT: %w", err)
	}

	return nil
}
