package cachaca

import (
	"context"
	"net/http"

	"github.com/unsafesystems/cachaca/auth/nop"
	"google.golang.org/grpc/metadata"

	"github.com/gin-gonic/gin"

	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/auth"
	"github.com/rs/zerolog/log"
	cauth "github.com/unsafesystems/cachaca/auth"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
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
	creds := &cauth.Credentials{
		Certificates: nil,
		Headers:      nil,
	}

	if ctx.Request == nil {
		ctx.Request = &http.Request{}
	}

	tls := ctx.Request.TLS
	if tls != nil {
		creds.Certificates = tls.PeerCertificates
	}

	creds.Headers = ctx.Request.Header

	err := m.authorizer.AuthorizeHTTP(ctx, creds)
	if err != nil {
		log.Warn().Err(err).Msg("failed to authenticate")
		ctx.AbortWithStatus(http.StatusUnauthorized)

		return
	}
}

func (m *middleware) grpcMiddleware(ctx context.Context) (context.Context, error) {
	creds := &cauth.Credentials{
		Certificates: nil,
		Headers:      nil,
	}

	p, ok := peer.FromContext(ctx)
	if ok {
		if mtls, ok := p.AuthInfo.(credentials.TLSInfo); ok {
			creds.Certificates = mtls.State.PeerCertificates
		}
	}

	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		log.Warn().Msg("failed to get metadata from context")

		return nil, status.Error(codes.Unauthenticated, "unauthenticated")
	}

	creds.Headers = http.Header(md)

	ctx, err := m.authorizer.AuthorizeGrpc(ctx, creds)
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
