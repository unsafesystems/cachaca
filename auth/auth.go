package auth

import (
	"context"
	"crypto/x509"

	"github.com/dgrijalva/jwt-go"
)

type AuthenticationKey struct{}

type Authentication struct {
	Certificates []*x509.Certificate
	Token        jwt.Claims
}

func WithCreds(ctx context.Context, authentication Authentication) context.Context {
	return context.WithValue(ctx, AuthenticationKey{}, authentication)
}

func GetCreds(ctx context.Context) (*Authentication, bool) {
	authentication, ok := ctx.Value(AuthenticationKey{}).(Authentication)

	return &authentication, ok
}
