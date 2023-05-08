package oidc

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/zitadel/oidc/v2/pkg/oidc"
)

func TestURLOptions(t *testing.T) {
	authorizer := &Authorizer{}

	opt := WithLoginURL("http://example.com/login")
	opt.apply(authorizer)
	assert.Equal(t, "http://example.com/login", authorizer.loginURL)

	opt = WithLogoutURL("http://example.com/logout")
	opt.apply(authorizer)
	assert.Equal(t, "http://example.com/logout", authorizer.logoutURL)

	opt = WithCallbackURL("http://example.com/redirect")
	opt.apply(authorizer)
	assert.Equal(t, "http://example.com/redirect", authorizer.callbackURL)

	opt = WithErrorURL("http://example.com/error")
	opt.apply(authorizer)
	assert.Equal(t, "http://example.com/error", authorizer.errorURL)

	opt = WithSuccessURL("http://example.com/success")
	opt.apply(authorizer)
	assert.Equal(t, "http://example.com/success", authorizer.successURL)

	assert.Equal(t, "http://example.com/login", authorizer.loginURL)
	assert.Equal(t, "http://example.com/logout", authorizer.logoutURL)
	assert.Equal(t, "http://example.com/redirect", authorizer.callbackURL)
	assert.Equal(t, "http://example.com/error", authorizer.errorURL)
	assert.Equal(t, "http://example.com/success", authorizer.successURL)
}

func TestWithTokenCallback(t *testing.T) {
	authorizer := &Authorizer{}

	callback := func(tokens *oidc.Tokens[*oidc.IDTokenClaims], userInfo *oidc.UserInfo) (interface{}, error) {
		return "test", nil
	}

	opt := WithTokenCallback(callback)
	opt.apply(authorizer)

	res, err := authorizer.tokenCallback(nil, nil)
	assert.NoError(t, err)
	assert.Equal(t, "test", res)
}
