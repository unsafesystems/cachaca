package nop

import (
	"context"

	"github.com/gin-gonic/gin"
)

// Authorizer is a no-operation authorizer. It simply passes all requests through and does not modify the context.
// This authorizer will be used automatically if no other authorizer is set.
type Authorizer struct{}

// NewAuthorizer returns a new no-operation authorizer.
func NewAuthorizer() *Authorizer {
	return &Authorizer{}
}

// AuthorizeGrpc is the middleware for grpc requests that injects credentials into the context.
func (authorizer *Authorizer) AuthorizeGrpc(ctx context.Context) (context.Context, error) {
	return ctx, nil
}

// AuthorizeHTTP is the middleware for http requests that injects credentials into the context.
func (authorizer *Authorizer) AuthorizeHTTP(_ *gin.Context) error {
	return nil
}
