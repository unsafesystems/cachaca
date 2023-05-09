package cachaca

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/unsafesystems/cachaca/auth/nop"

	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/auth"
	"github.com/rs/zerolog/log"
	cauth "github.com/unsafesystems/cachaca/auth"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type middleware struct {
	authorizer cauth.Authorizer
}

func newMiddleware(authorizer cauth.Authorizer) *middleware {
	if authorizer == nil {
		log.Warn().Msg("no authorizer configured - using nop authorizer")

		authorizer = nop.NewAuthorizer()
	}

	return &middleware{
		authorizer,
	}
}

func (m *middleware) ginMiddleware(ctx *gin.Context) {
	err := m.authorizer.AuthorizeHTTP(ctx)
	if err != nil {
		log.Warn().Err(err).Msg("failed to authenticate")
		ctx.AbortWithStatus(http.StatusUnauthorized)

		return
	}
}

func (m *middleware) grpcMiddleware(ctx context.Context) (context.Context, error) {
	ctx, err := m.authorizer.AuthorizeGrpc(ctx)
	if err != nil {
		log.Warn().Err(err).Msg("failed to authenticate")

		return nil, status.Error(codes.Unauthenticated, "unauthenticated")
	}

	return ctx, nil
}

func (m *middleware) unaryServerInterceptor() grpc.UnaryServerInterceptor {
	return auth.UnaryServerInterceptor(m.grpcMiddleware)
}

func (m *middleware) streamServerInterceptor() grpc.StreamServerInterceptor {
	return auth.StreamServerInterceptor(m.grpcMiddleware)
}
