//nolint:ireturn
package oidc

import (
	"context"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/zitadel/oidc/v2/pkg/oidc"

	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/zitadel/oidc/v2/pkg/client/rp"
)

// Credentials represents the (validated) client credentials. It directly exposes the standard JWT claims that were
// provided by the client. Custom claims can be retrieved using the `GetCustomClaims` method.
// To reduce calls to the storage backend, credentials lazy loads the OAuth2/OIDC tokens/sessions if requested through
// the `GetSession` method.
type Credentials struct {
	jwt.Claims
	token    string
	storage  Storage
	provider rp.RelyingParty
}

func (c *Credentials) GetCustomClaims(claims ...interface{}) error {
	tok, err := jwt.ParseSigned(c.token)
	if err != nil {
		return fmt.Errorf("failed to parse token: %w", err)
	}

	err = tok.UnsafeClaimsWithoutVerification(claims...)
	if err != nil {
		return fmt.Errorf("failed to get claims: %w", err)
	}

	return nil
}

func (c *Credentials) GetSession(ctx context.Context) (*Session, error) {
	sessionID := c.ID
	if sessionID == "" {
		return nil, ErrMissingSessionID
	}

	session, err := c.storage.Get(ctx, sessionID)
	if err != nil {
		return nil, fmt.Errorf("failed to get session: %w", err)
	}

	session.provider = c.provider

	return session, nil
}

func (c *Credentials) Refresh(ctx context.Context) error {
	session, err := c.GetSession(ctx)
	if err != nil {
		return fmt.Errorf("failed to get session: %w", err)
	}

	if err := session.refresh(ctx); err != nil {
		return fmt.Errorf("failed to refresh: %w", err)
	}

	return nil
}

// GetProvider returns the Relying Party associated with these credentials. The Relying Party exposes an OAuth-enabled
// http.Client that can be used to communicate with the Relying Party.
//

func (c *Credentials) GetProvider() rp.RelyingParty {
	return c.provider
}

type Session struct {
	*oidc.Tokens[*oidc.IDTokenClaims]
	ID       string         `json:"id"`
	UserInfo *oidc.UserInfo `json:"userInfo,omitempty"`
	Issuer   string         `json:"issuer,omitempty"`
	provider rp.RelyingParty
	dirty    bool
}

func NewSessionFromCodeExchange(ctx context.Context, code string, provider rp.RelyingParty) (*Session, error) {
	tokens, err := rp.CodeExchange[*oidc.IDTokenClaims](ctx, code, provider)
	if err != nil {
		return nil, fmt.Errorf("code exchange failed: %w", err)
	}

	// The OWASP and NIST recommendations suggest that session keys should be at least 128 bits in length to resist
	// cryptographic attacks and provide an acceptable level of security. But 512 is also "only" 64 bytes...
	sessionKey, err := generateSecureKey(SessionKeyBitLength)
	if err != nil {
		return nil, fmt.Errorf("session key generation failed: %w", err)
	}

	session := &Session{
		ID:       sessionKey,
		Tokens:   tokens,
		Issuer:   provider.Issuer(),
		provider: provider,
		dirty:    true,
	}

	err = session.refresh(ctx)
	if err != nil {
		return nil, fmt.Errorf("session refresh failed: %w", err)
	}

	return session, nil
}

func (sess *Session) refresh(ctx context.Context) error {
	if time.Until(sess.Expiry) < 10*time.Minute {
		// Update access and refresh tokens
		tokens, err := rp.RefreshAccessToken(sess.provider, sess.RefreshToken, "", "")
		if err != nil {
			return fmt.Errorf("failed to refresh using access token: %w", err)
		}

		sess.Token = tokens
		sess.dirty = true
	}

	// Make sure the sess expiry is limited to MaxSessionAge
	if time.Until(sess.Expiry) > MaxSessionAge {
		sess.Expiry = time.Now().Add(MaxSessionAge)
	}

	if sess.provider.IsOAuth2Only() {
		return nil
	}

	// Update the id token if available
	tokenStr, ok := sess.Extra("id_token").(string)
	if ok {
		sess.IDToken = tokenStr
	}

	if sess.IDToken != "" {
		token, err := rp.VerifyTokens[*oidc.IDTokenClaims](
			ctx,
			sess.AccessToken,
			sess.IDToken,
			sess.provider.IDTokenVerifier(),
		)
		if err != nil {
			return fmt.Errorf("failed to verify id_token: %w", err)
		}

		sess.IDTokenClaims = token
	}

	// Not sure if this is a common problem - at least mockoidc returns "bearer" but expects "Bearer"
	if sess.TokenType == "bearer" {
		sess.TokenType = "Bearer"
	}

	// Update the user info
	userInfo, err := rp.Userinfo(sess.AccessToken, sess.TokenType, sess.IDTokenClaims.GetSubject(), sess.provider)
	if err != nil {
		return fmt.Errorf("failed to get userinfo: %w", err)
	}

	sess.UserInfo = userInfo
	sess.dirty = true

	return nil
}

func (sess *Session) generateJWT(ctx context.Context, signer jose.Signer, callback SessionCallbackFunc,
) (string, error) {
	if sess.ID == "" {
		return "", ErrMissingSessionID
	}

	subject := ""
	if sess.IDTokenClaims != nil {
		subject = sess.IDTokenClaims.GetSubject()
	}

	stdClaims := jwt.Claims{
		ID:        sess.ID,
		Subject:   subject,
		Issuer:    sess.Issuer,
		Expiry:    jwt.NewNumericDate(sess.Expiry),
		NotBefore: jwt.NewNumericDate(time.Now()),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
	}

	builder := jwt.Signed(signer).Claims(stdClaims)

	if callback != nil {
		claims, err := callback(ctx, sess)
		if err != nil {
			return "", err
		}

		if claims != nil {
			builder = builder.Claims(claims)
		}
	}

	token, err := builder.CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("failed to generate JWT: %w", err)
	}

	if len(token) >= MaxSessionKeyLength {
		return "", ErrSessionTokenTooLong
	}

	return token, nil
}
