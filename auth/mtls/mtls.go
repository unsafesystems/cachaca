package mtls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"

	"github.com/gin-gonic/gin"
	"github.com/unsafesystems/cachaca"
	"github.com/unsafesystems/cachaca/auth"
)

var ErrMissingClientCertificates = errors.New("no client certificates provided")

// Authorizer is a mTLS enabled authorizer that requires clients to present a valid client certificate for connection.
// Client certificates will be checked against a pool of CA certificates. The authorizer also configures TLS for the
// server.
type Authorizer struct {
	Pool         *x509.CertPool
	Certificates []tls.Certificate
}

// Credentials are passed into the context by the middleware and can be used to retrieve the certificates / certificate
// chain of the authenticated client connecting to the server.
type Credentials struct {
	Certificates []*x509.Certificate
}

// NewAuthorizer creates a new mTLS authorizer. The certificate pool is used to validate the client certificates, while
// the server certificates are used to enable TLS on the server.
func NewAuthorizer(pool *x509.CertPool, serverCertificates []tls.Certificate) *Authorizer {
	return &Authorizer{
		Pool:         pool,
		Certificates: serverCertificates,
	}
}

// Apply implements the cachaca.Option interface to configure the server to use this authorizer.
func (authorizer *Authorizer) Apply(server *cachaca.Server) error {
	server.Authorizer = authorizer
	server.TLSConfig = &tls.Config{
		MinVersion:   tls.VersionTLS12,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    authorizer.Pool,
		Certificates: authorizer.Certificates,
	}

	return nil
}

// AuthorizeGrpc serves as the middleware to authorize the incoming gRPC requests. If no client certificates are
// provided, the request will be rejected. Provided certificates are injected into the context by the middleware.
func (authorizer *Authorizer) AuthorizeGrpc(ctx context.Context) (context.Context, error) {
	p, ok := peer.FromContext(ctx)
	if ok {
		if mtls, ok := p.AuthInfo.(credentials.TLSInfo); ok {
			return auth.WithCredentials(ctx, &Credentials{mtls.State.PeerCertificates}), nil
		}
	}

	return nil, ErrMissingClientCertificates
}

// AuthorizeHTTP serves as the middleware to authorize the incoming HTTP requests. If no client certificates are
// provided, the request will be rejected. Provided certificates are injected into the context by the middleware.
func (authorizer *Authorizer) AuthorizeHTTP(ctx *gin.Context) error {
	req := ctx.Request
	if req == nil {
		return ErrMissingClientCertificates
	}

	tlsConfig := ctx.Request.TLS
	if tlsConfig != nil {
		auth.WithCredentials(ctx, &Credentials{tlsConfig.PeerCertificates})

		return nil
	}

	return ErrMissingClientCertificates
}
