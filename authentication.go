package cachaca

import (
	"context"
	"reflect"

	"github.com/golang-jwt/jwt/v5"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/auth"
	"github.com/rs/zerolog/log"
	auth2 "github.com/unsafesystems/cachaca/auth"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

type AuthenticationMiddleware struct {
	jwtKeyFunc jwt.Keyfunc
	jwtToken   jwt.Claims
}

func NewAuthenticationMiddleware(jwtKeyFunc jwt.Keyfunc, jwtToken jwt.Claims) *AuthenticationMiddleware {
	return &AuthenticationMiddleware{
		jwtKeyFunc,
		jwtToken,
	}
}

func (middleware *AuthenticationMiddleware) Middleware(ctx context.Context) (context.Context, error) {
	authentication := auth2.Authentication{
		Certificates: nil,
		Token:        nil,
	}

	p, ok := peer.FromContext(ctx)
	if ok {
		if mtls, ok := p.AuthInfo.(credentials.TLSInfo); ok {
			authentication.Certificates = mtls.State.PeerCertificates
		}
	}

	tokenStr, err := auth.AuthFromMD(ctx, "bearer")
	if err == nil {
		token, err := jwt.ParseWithClaims(tokenStr, middleware.jwtToken, middleware.jwtKeyFunc)
		if err != nil {
			log.Warn().Err(err).Msg("failed to parse token")

			return nil, status.Error(codes.Unauthenticated, "unauthenticated")
		}

		if reflect.TypeOf(token.Claims) != reflect.TypeOf(middleware.jwtToken) {
			log.Warn().Msg("failed to parse token")

			return nil, status.Error(codes.Unauthenticated, "unauthenticated")
		}

		authentication.Token = token.Claims
	}

	if authentication.Certificates == nil && authentication.Token == nil {
		return nil, status.Error(codes.Unauthenticated, "unauthenticated")
	}

	return auth2.WithCreds(ctx, authentication), nil
}

func (middleware *AuthenticationMiddleware) UnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return auth.UnaryServerInterceptor(middleware.Middleware)
}

func (middleware *AuthenticationMiddleware) StreamServerInterceptor() grpc.StreamServerInterceptor {
	return auth.StreamServerInterceptor(middleware.Middleware)
}
