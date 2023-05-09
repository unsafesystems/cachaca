package nop

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestNopAuthorizer_Gin(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())

	authorizer := NewAuthorizer()
	err := authorizer.AuthorizeHTTP(ctx)
	assert.NoError(t, err)
}

func TestNopAuthorizer_Grpc(t *testing.T) {
	ctx := context.Background()

	authorizer := NewAuthorizer()
	ctx2, err := authorizer.AuthorizeGrpc(ctx)
	assert.NoError(t, err)
	assert.Equal(t, ctx2, ctx)
}
