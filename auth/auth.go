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

func GetCreds[T any](ctx any) (*Credentials, bool) {
	switch ctx := ctx.(type) {
	case *gin.Context:
		creds, ok := ctx.Get(ginKey)

		if !ok {
			return nil, ok
		}

		authentication, ok := creds.(*Credentials)

		return authentication, ok
	case context.Context:
		creds, ok := ctx.Value(AuthenticationKey{}).(*Credentials)

		return creds, ok
	default:
		return nil, false
	}
}

func WithCreds(ctx any, creds *Credentials) context.Context {
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
