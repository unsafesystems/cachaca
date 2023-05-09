package oidc

import (
	"context"
	"testing"

	"github.com/go-jose/go-jose/v3"

	"github.com/stretchr/testify/assert"
)

func TestURLOptions(t *testing.T) {
	key := &jose.SigningKey{Algorithm: "HS256", Key: []byte("secret")}

	authorizer := NewAuthorizer(
		key,
		WithLoginURL("http://example.com/login"),
		WithLogoutURL("http://example.com/logout"),
		WithCallbackURL("http://example.com/redirect"),
		WithErrorURL("http://example.com/error"),
		WithSuccessURL("http://example.com/success"),
	)

	assert.Equal(t, "http://example.com/login", authorizer.loginURL)
	assert.Equal(t, "http://example.com/logout", authorizer.logoutURL)
	assert.Equal(t, "http://example.com/redirect", authorizer.callbackURL)
	assert.Equal(t, "http://example.com/error", authorizer.errorURL)
	assert.Equal(t, "http://example.com/success", authorizer.successURL)
}

func TestWithTokenCallback(t *testing.T) {
	authorizer := &Authorizer{}

	callback := func(ctx context.Context, session *Session) (interface{}, error) {
		return "test", nil
	}

	opt := WithTokenCallback(callback)
	opt.apply(authorizer)

	res, err := authorizer.sessionCallback(nil, nil)
	assert.NoError(t, err)
	assert.Equal(t, "test", res)
}
