package auth

import (
	"context"
	"fmt"

	"github.com/gin-gonic/gin"
)

type Authorizer interface {
	AuthorizeGrpc(ctx context.Context) (context.Context, error)
	AuthorizeHTTP(ctx *gin.Context) error
}

type AuthenticationKey string

func GetCredentials[T any](ctx any) (*T, bool) {
	switch ctx := ctx.(type) {
	case *gin.Context:
		creds, ok := ctx.Get(typeS[T]())

		if !ok {
			return nil, ok
		}

		authentication, ok := creds.(*T)

		return authentication, ok
	case context.Context:
		creds, ok := ctx.Value(AuthenticationKey(typeS[T]())).(*T)

		return creds, ok
	default:
		return nil, false
	}
}

func WithCredentials[T any](ctx any, creds *T) context.Context {
	switch ctx := ctx.(type) {
	case *gin.Context:
		ctx.Set(typeS[T](), creds)

		return nil
	case context.Context:
		ctx = context.WithValue(ctx, AuthenticationKey(typeS[T]()), creds)

		return ctx
	default:
		return nil
	}
}

func typeS[T any]() string {
	return "cachaca:" + fmt.Sprintf("%T", *new(T))
}
