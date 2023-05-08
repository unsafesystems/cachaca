package mtls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"

	"github.com/gin-gonic/gin"
	"github.com/unsafesystems/cachaca"
	"github.com/unsafesystems/cachaca/auth"
)

var ErrMissingClientCertificates = errors.New("no client certificates provided")

type Authorizer struct {
	Pool         *x509.CertPool
	Certificates []tls.Certificate
}

type Credentials struct {
	Certificates []*x509.Certificate
}

func NewAuthorizer(pool *x509.CertPool, serverCertificates []tls.Certificate) *Authorizer {
	return &Authorizer{
		Pool:         pool,
		Certificates: serverCertificates,
	}
}

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

func (authorizer *Authorizer) AuthorizeGrpc(ctx context.Context, creds *auth.Credentials) (context.Context, error) {
	if creds == nil || len(creds.Certificates) == 0 {
		return nil, ErrMissingClientCertificates
	}

	return auth.WithCreds(ctx, &Credentials{Certificates: creds.Certificates}), nil
}

func (authorizer *Authorizer) AuthorizeHTTP(ctx *gin.Context, creds *auth.Credentials) error {
	if creds == nil || len(creds.Certificates) == 0 {
		return ErrMissingClientCertificates
	}

	auth.WithCreds(ctx, &Credentials{Certificates: creds.Certificates})

	return nil
}
