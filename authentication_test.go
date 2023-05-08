//nolint
package cachaca

import (
	"context"
	"errors"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"
	"github.com/unsafesystems/cachaca/auth"
	"github.com/unsafesystems/cachaca/mocks"
	"google.golang.org/grpc/metadata"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNoAuthorizer(t *testing.T) {
	zerolog.SetGlobalLevel(zerolog.Disabled)
	m := newMiddleware(nil)
	assert.NotNil(t, m.authorizer)
}

func TestHttpAuthorizerCalled(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	zerolog.SetGlobalLevel(zerolog.Disabled)
	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	authorizer := mocks.NewAuthorizer(t)
	authorizer.On("AuthorizeHTTP", ctx, &auth.Credentials{}).Return(nil).Once()

	m := newMiddleware(authorizer)
	m.ginMiddleware(ctx)
	assert.False(t, ctx.IsAborted())
}

func TestHttpAuthorizerFail(t *testing.T) {
	gin.SetMode(gin.ReleaseMode)
	zerolog.SetGlobalLevel(zerolog.Disabled)
	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	authorizer := mocks.NewAuthorizer(t)
	authorizer.On("AuthorizeHTTP", ctx, &auth.Credentials{}).Return(errors.New("test")).Once()

	m := newMiddleware(authorizer)
	m.ginMiddleware(ctx)
	assert.True(t, ctx.IsAborted())
	assert.Equal(t, http.StatusUnauthorized, ctx.Writer.Status())
}

func TestGrpcAuthorizerCalled(t *testing.T) {
	ctx := metadata.NewIncomingContext(context.Background(), nil)
	authorizer := mocks.NewAuthorizer(t)
	authorizer.On("AuthorizeGrpc", ctx, &auth.Credentials{Headers: http.Header{}}).Return(ctx, nil).Once()

	m := newMiddleware(authorizer)
	ctx, err := m.grpcMiddleware(ctx)
	assert.NoError(t, err)
	assert.Equal(t, ctx, ctx)
}

func TestGrpcAuthorizerFail(t *testing.T) {
	ctx := metadata.NewIncomingContext(context.Background(), nil)
	authorizer := mocks.NewAuthorizer(t)
	authorizer.On("AuthorizeGrpc", ctx, &auth.Credentials{Headers: http.Header{}}).Return(nil, errors.New("test")).Once()

	m := newMiddleware(authorizer)
	ctx, err := m.grpcMiddleware(ctx)
	assert.Error(t, err)
	assert.Nil(t, ctx)
}

func TestGrpcMissingMetadata(t *testing.T) {
	ctx := context.Background()

	m := newMiddleware(nil)
	ctx, err := m.grpcMiddleware(ctx)
	assert.Error(t, err)
	assert.Nil(t, ctx)
}
