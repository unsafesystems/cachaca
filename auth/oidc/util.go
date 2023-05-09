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
)

const (
	maxStateCookieAge   = 15 * time.Minute
	MaxSessionKeyLength = 4096
	StateKeyBitLength   = 256
	BitsPerByte         = 8
)

var (
	ErrSessionTokenTooLong       = errors.New("session token too long")
	ErrStateMismatch             = errors.New("state mismatch")
	ErrAlgorithmValidationFailed = errors.New("algorithm validation failed")
	ErrTokenHeaderMissing        = errors.New("token header missing")
)

type state struct {
	id       string
	Redirect string `json:"redirect"`
	Data     string `json:"data"`
}

func newState(ctx *gin.Context) (*state, error) {
	stateKey, err := generateSecureKey(StateKeyBitLength)
	if err != nil {
		return nil, err
	}

	return &state{
		id:       stateKey,
		Redirect: ctx.Query("redirect"),
		Data:     ctx.Query("data"),
	}, nil
}

func validateState(ctx *gin.Context, signingKey *jose.SigningKey, expected string) (*state, error) {
	cookie, err := ctx.Cookie(cookieName(ctx, "state"))
	if err != nil {
		return nil, fmt.Errorf("state cookie missing: %w", err)
	}

	stdClaims := new(jwt.Claims)
	stateClaims := new(state)

	err = parseJWT(cookie, signingKey, stdClaims, stateClaims)
	if err != nil {
		return nil, err
	}

	err = stdClaims.Validate(jwt.Expected{
		ID:       "state",
		Time:     time.Now(),
		Audience: jwt.Audience{"state"},
	})
	if err != nil {
		return nil, fmt.Errorf("state cookie invalid: %w", err)
	}

	if len(expected) == 0 || stdClaims.Subject != expected {
		return nil, ErrStateMismatch
	}

	return stateClaims, nil
}

func (s *state) attachState(ctx *gin.Context, signer jose.Signer) error {
	stdClaims := jwt.Claims{
		ID:        "state",
		Issuer:    "",
		Subject:   s.id,
		Audience:  []string{"state"},
		Expiry:    jwt.NewNumericDate(time.Now().Add(maxStateCookieAge)),
		NotBefore: jwt.NewNumericDate(time.Now()),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
	}

	token, err := jwt.Signed(signer).Claims(stdClaims).Claims(s).CompactSerialize()
	if err != nil {
		return fmt.Errorf("failed to serialize state token: %w", err)
	}

	ctx.SetCookie(cookieName(ctx, "state"), token, int(maxStateCookieAge.Seconds()), "/", "",
		isHTTPS(ctx), true)

	return nil
}

func (s *state) redirect(ctx *gin.Context, defaultURL string) {
	if s.Redirect != "" {
		ctx.Redirect(http.StatusFound, s.Redirect)

		return
	}

	// The continuation_key is intended to be used in e.g. a SPA or native client to continue the flow after the
	// redirect. There we don't want or need a redirect but instead can use any value from JSON.
	if s.Data != "" {
		ctx.JSON(http.StatusOK, gin.H{
			"data": s.Data,
		})

		return
	}

	ctx.Redirect(http.StatusFound, defaultURL)
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
	req := ctx.Request

	return (req.URL.IsAbs() && req.URL.Scheme == "https") || req.TLS != nil
}

func cookieName(ctx *gin.Context, name string) string {
	// __Host- prefix according to https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies for increased security
	cookieName := fmt.Sprintf("__Host-%s-%s", CookiePrefix, name)
	if !isHTTPS(ctx) {
		cookieName = fmt.Sprintf("%s-%s", CookiePrefix, name)
	}

	return cookieName
}

func parseJWT(token string, key *jose.SigningKey, claims ...interface{}) error {
	tok, err := jwt.ParseSigned(token)
	if err != nil {
		return fmt.Errorf("failed to parse JWT: %w", err)
	}

	if len(tok.Headers) < 1 {
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
