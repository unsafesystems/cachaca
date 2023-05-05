package auth

import (
	"context"
	"crypto/x509"
	"net/http"

	"github.com/gin-gonic/gin"
)

const ginKey = "cachaca_creds"

type Credentials struct {
	Certificates []*x509.Certificate
	Headers      http.Header
}

type Authorizer interface {
	AuthorizeGrpc(ctx context.Context, creds *Credentials) (context.Context, error)
	AuthorizeHTTP(ctx *gin.Context, creds *Credentials) error
}

type AuthenticationKey struct{}

func GetCreds[T any](ctx any) (*T, bool) {
	switch ctx := ctx.(type) {
	case *gin.Context:
		creds, ok := ctx.Get(ginKey)

		if !ok {
			return nil, ok
		}

		authentication, ok := creds.(*T)

		return authentication, ok
	case context.Context:
		creds, ok := ctx.Value(AuthenticationKey{}).(*T)

		return creds, ok
	default:
		return nil, false
	}
}

func WithCreds[T any](ctx any, creds *T) context.Context {
	switch ctx := ctx.(type) {
	case *gin.Context:
		ctx.Set(ginKey, creds)

		return nil
	case context.Context:
		ctx = context.WithValue(ctx, AuthenticationKey{}, creds)

		return ctx
	default:
		return nil
	}
}
