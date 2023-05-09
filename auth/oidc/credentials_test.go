//nolint
package oidc

import (
	"context"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zitadel/oidc/v2/pkg/client/rp"
	"golang.org/x/oauth2"
	"testing"
)

func TestCredentialsCustomClaims(t *testing.T) {
	type customClaims struct {
		Name string `json:"name"`
	}

	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.XbPfbIHMI6arZ3Y922BhjWgQzWXcXNrz0ogtVhfEd2o"

	// Note that we only pass the token.
	// We assume that the token is valid because we validate it when creating the credentials.
	creds := Credentials{
		token: token,
	}

	claims := new(customClaims)
	err := creds.GetCustomClaims(claims)
	assert.Nil(t, err)
	assert.Equal(t, "John Doe", claims.Name)
}

func TestCredentialsCustomClaimsFailedParsing(t *testing.T) {
	type customClaims struct {
		Name string `json:"name"`
	}

	token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3DkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.XbPfbIHMI6arZ3Y922BhjWgQzWXcXNrz0ogtVhfEd2o"

	// Note that we only pass the token.
	// We assume that the token is valid because we validate it when creating the credentials.
	creds := Credentials{
		token: token,
	}

	claims := new(customClaims)
	err := creds.GetCustomClaims(claims)
	assert.Error(t, err)
}

func TestCredentialsGetSession(t *testing.T) {
	creds := Credentials{}
	_, err := creds.GetSession(context.Background())
	assert.Error(t, err)

	// We don't actually use the rp but need to check that it gets passed into the session.
	provider, err := rp.NewRelyingPartyOAuth(&oauth2.Config{
		ClientID:     "clientID",
		ClientSecret: "clientSecret",
		Endpoint: oauth2.Endpoint{
			AuthURL:   "http://localhost:8080/auth",
			TokenURL:  "http://localhost:8080/token",
			AuthStyle: oauth2.AuthStyleInHeader,
		},
		RedirectURL: "redirectURL",
		Scopes:      nil,
	})
	assert.NoError(t, err)

	storage := NewMemoryStorage()

	id := uuid.NewString()
	creds = Credentials{
		Claims: jwt.Claims{
			ID: id,
		},
		provider: provider,
		storage:  storage,
	}

	assert.Equal(t, provider, creds.GetProvider())

	_, err = creds.GetSession(context.Background())
	require.Error(t, err)

	err = storage.Set(context.Background(), &Session{
		ID:     id,
		Issuer: "test",
	})
	require.NoError(t, err)

	session, err := creds.GetSession(context.Background())
	require.NoError(t, err)
	assert.Equal(t, provider, session.provider)
	assert.Equal(t, "test", session.Issuer)
}

func TestSessionEnsureID(t *testing.T) {
	session := &Session{}
	_, err := session.generateJWT(context.Background(), nil, nil)
	assert.Error(t, err)
}
