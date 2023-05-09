package mtls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"

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

	clientCerts := []*x509.Certificate{{}}

	{
		// GRPC validation - missing client certificates
		ctx := metadata.NewIncomingContext(context.Background(), nil)
		_, err = authorizer.AuthorizeGrpc(ctx)
		assert.Error(t, err)

		// GRPC validation - certificates are present
		ctx = metadata.NewIncomingContext(context.Background(), nil)
		ctx = peer.NewContext(ctx, &peer.Peer{
			AuthInfo: credentials.TLSInfo{
				State: tls.ConnectionState{
					PeerCertificates: clientCerts,
				},
			},
		})
		ctx, err = authorizer.AuthorizeGrpc(ctx)
		assert.NoError(t, err)
		res, ok := auth.GetCredentials[Credentials](ctx)
		assert.True(t, ok)
		assert.Equal(t, res.Certificates, clientCerts)
	}

	{
		// HTTP validation - missing client certificates
		ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
		err = authorizer.AuthorizeHTTP(ctx)
		assert.Error(t, err)

		// HTTP validation - certificates are present
		ctx, _ = gin.CreateTestContext(httptest.NewRecorder())
		ctx.Request = &http.Request{
			TLS: &tls.ConnectionState{
				PeerCertificates: clientCerts,
			},
		}
		err = authorizer.AuthorizeHTTP(ctx)
		assert.NoError(t, err)
		res, ok := auth.GetCredentials[Credentials](ctx)
		assert.True(t, ok)
		assert.Equal(t, res.Certificates, clientCerts)
	}
}
