package nop

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/unsafesystems/cachaca/auth"
)

func TestNopAuthorizer_Gin(t *testing.T) {
	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	creds := &auth.Credentials{}

	authorizer := NewAuthorizer()

	err := authorizer.AuthorizeHTTP(ctx, creds)
	assert.NoError(t, err)

	res, ok := auth.GetCreds[auth.Credentials](ctx)
	require.True(t, ok)
	assert.Equal(t, creds, res)
}

func TestNopAuthorizer_Grpc(t *testing.T) {
	ctx := context.Background()
	creds := &auth.Credentials{}

	authorizer := NewAuthorizer()

	ctx, err := authorizer.AuthorizeGrpc(ctx, creds)
	assert.NoError(t, err)

	res, ok := auth.GetCreds[auth.Credentials](ctx)
	require.True(t, ok)
	assert.Equal(t, creds, res)
}
