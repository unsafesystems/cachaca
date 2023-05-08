package nop

import (
	"context"

	"github.com/gin-gonic/gin"

	"github.com/unsafesystems/cachaca/auth"
)

type Authorizer struct{}

func NewAuthorizer() *Authorizer {
	return &Authorizer{}
}

func (authorizer *Authorizer) AuthorizeGrpc(ctx context.Context, creds *auth.Credentials) (context.Context, error) {
	return auth.WithCreds(ctx, creds), nil
}

func (authorizer *Authorizer) AuthorizeHTTP(ctx *gin.Context, creds *auth.Credentials) error {
	auth.WithCreds(ctx, creds)

	return nil
}
