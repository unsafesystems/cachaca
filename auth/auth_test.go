//nolint
package auth

import (
	"context"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"net/http/httptest"
	"testing"
)

func TestAuth(t *testing.T) {
	ctx := context.Background()

	creds, ok := GetCreds[Credentials](ctx)
	assert.False(t, ok)

	auth := Credentials{}
	ctx = WithCreds(ctx, &auth)

	creds, ok = GetCreds[Credentials](ctx)
	assert.True(t, ok)
	assert.Equal(t, auth, *creds)
}

func TestGinAuth(t *testing.T) {
	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())

	creds, ok := GetCreds[Credentials](ctx)
	assert.False(t, ok)

	auth := Credentials{}
	_ = WithCreds(ctx, &auth)

	creds, ok = GetCreds[Credentials](ctx)
	assert.True(t, ok)
	assert.Equal(t, auth, *creds)
}

func TestUnknownContext(t *testing.T) {
	// We only support gin.Context and context.Context - so that should simply be a noop
	ctx := "test"

	res := WithCreds(ctx, &Credentials{})
	assert.Nil(t, res)

	val, ok := GetCreds[Credentials](ctx)
	assert.False(t, ok)
	assert.Nil(t, val)
}
