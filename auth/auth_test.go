//nolint
package auth

import (
	"context"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"net/http/httptest"
	"testing"
)

type Credentials struct{}

func TestAuth(t *testing.T) {
	ctx := context.Background()

	creds, ok := GetCredentials[Credentials](ctx)
	assert.False(t, ok)

	auth := Credentials{}
	ctx = WithCredentials(ctx, &auth)

	creds, ok = GetCredentials[Credentials](ctx)
	assert.True(t, ok)
	assert.Equal(t, auth, *creds)
}

func TestGinAuth(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())

	creds, ok := GetCredentials[Credentials](ctx)
	assert.False(t, ok)

	auth := Credentials{}
	_ = WithCredentials(ctx, &auth)

	creds, ok = GetCredentials[Credentials](ctx)
	assert.True(t, ok)
	assert.Equal(t, auth, *creds)
}

func TestUnknownContext(t *testing.T) {
	// We only support gin.Context and context.Context - so that should simply be a noop
	ctx := "test"

	res := WithCredentials(ctx, &Credentials{})
	assert.Nil(t, res)

	val, ok := GetCredentials[Credentials](ctx)
	assert.False(t, ok)
	assert.Nil(t, val)
}
