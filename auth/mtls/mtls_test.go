package mtls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/unsafesystems/cachaca"
	"github.com/unsafesystems/cachaca/auth"
	"google.golang.org/grpc/metadata"
)

func TestApply(t *testing.T) {
	pool := x509.NewCertPool()
	certs := []tls.Certificate{}
	authorizer := NewAuthorizer(pool, certs)
	server, err := cachaca.NewServer(authorizer)
	require.NoError(t, err)

	assert.Equal(t, authorizer, server.Authorizer)
	assert.Equal(t, pool, server.TLSConfig.ClientCAs)
	assert.Equal(t, tls.RequireAndVerifyClientCert, server.TLSConfig.ClientAuth)
	assert.Equal(t, tls.VersionTLS12, int(server.TLSConfig.MinVersion))
	assert.Equal(t, certs, server.TLSConfig.Certificates)

	{
		// GRPC validation - missing client certificates
		ctx := metadata.NewIncomingContext(context.Background(), nil)
		creds := &auth.Credentials{}
		_, err = authorizer.AuthorizeGrpc(ctx, creds)
		assert.Error(t, err)

		// GRPC validation - certificates are present
		ctx = metadata.NewIncomingContext(context.Background(), nil)
		creds = &auth.Credentials{Certificates: []*x509.Certificate{{}}}
		ctx, err = authorizer.AuthorizeGrpc(ctx, creds)
		assert.NoError(t, err)
		res, ok := auth.GetCreds[Credentials](ctx)
		assert.True(t, ok)
		assert.Equal(t, res, &Credentials{Certificates: creds.Certificates})
	}

	{
		// HTTP validation - missing client certificates
		ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
		creds := &auth.Credentials{}
		err = authorizer.AuthorizeHTTP(ctx, creds)
		assert.Error(t, err)

		// HTTP validation - certificates are present
		ctx, _ = gin.CreateTestContext(httptest.NewRecorder())
		creds = &auth.Credentials{Certificates: []*x509.Certificate{{}}}
		err = authorizer.AuthorizeHTTP(ctx, creds)
		assert.NoError(t, err)
		res, ok := auth.GetCreds[Credentials](ctx)
		assert.True(t, ok)
		assert.Equal(t, res, &Credentials{Certificates: creds.Certificates})
	}
}
