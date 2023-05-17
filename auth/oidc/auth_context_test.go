//nolint
package oidc

import (
	"context"
	"encoding/json"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/unsafesystems/cachaca/auth/oidc/mocks"
	"github.com/zitadel/oidc/v2/pkg/oidc"
	"golang.org/x/oauth2"
	"testing"
	"time"
)

func TestAuthContext(t *testing.T) {
	suite.Run(t, new(AuthContextTSuite))
}

type AuthContextTSuite struct {
	suite.Suite
}

func (s *AuthContextTSuite) SetupSuite() {
}

func TestAuthContext_Expiry(t *testing.T) {
	now := time.Now()
	authContext := &AuthContext{
		nowF: func() time.Time {
			return now
		},
	}
	assert.True(t, authContext.Expiry().IsZero())

	authContext.updateExpiry(now)
	assert.Equal(t, now, authContext.Expiry())

	authContext.updateExpiry(time.Time{})
	assert.Equal(t, now, authContext.Expiry())

	authContext.updateExpiry(now.Add(2 * time.Hour))
	assert.Equal(t, now.Add(time.Hour), authContext.Expiry())
}

func TestAuthContext_Hydrate(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	authContext := &AuthContext{
		nowF: func() time.Time {
			return now
		},
		Hydrated: true,
	}

	// Already marked hydrated so nothing should happen
	err := authContext.Hydrate(ctx)
	assert.NoError(t, err)

	// Mark as not hydrated we will get an error because we are missing the provider
	authContext.Hydrated = false
	err = authContext.Hydrate(ctx)
	assert.ErrorIs(t, err, ErrInternal)

	// Let's populate the provider - but we are still missing the Access Token
	provider := mocks.NewProvider(t)
	authContext.provider = provider
	err = authContext.Hydrate(ctx)
	assert.ErrorIs(t, err, ErrBadRequest)

	// Let's populate the Access Token - now the provider will be called - but we error out
	accessToken := uuid.NewString()
	authContext.Token = oauth2.Token{
		TokenType:   "Bearer",
		AccessToken: accessToken,
	}
	provider.On("UserInfo", ctx, &authContext.Token).Return(nil, ErrBadRequest).Once()
	err = authContext.Hydrate(ctx)
	assert.Error(t, err)

	// Let's populate the Access Token - the provider will be called - and we get a UserInfo
	subject := uuid.NewString()
	provider.On("UserInfo", ctx, &authContext.Token).Return(&oidc.UserInfo{
		Subject: subject,
	}, nil).Once()
	err = authContext.Hydrate(ctx)
	assert.NoError(t, err)
	assert.True(t, authContext.Hydrated)
	assert.Equal(t, subject, authContext.Subject)
}

func TestAuthContext_NewAuthContext(t *testing.T) {
	ctx := context.Background()
	accessToken := uuid.NewString()
	provider := mocks.NewProvider(t)
	authContext := NewAuthContext(provider)

	// Error because there was an error with the call
	provider.On("Introspect", ctx, accessToken).Return(nil, ErrBadRequest).Once()
	err := authContext.Introspect(ctx, accessToken)
	assert.Error(t, err)

	// Error because the token is no longer active
	provider.On("Introspect", ctx, accessToken).Return(&oidc.IntrospectionResponse{
		Active: false,
	}, nil).Once()
	err = authContext.Introspect(ctx, accessToken)
	assert.ErrorIs(t, err, ErrBadRequest)

	// All good
	tt := time.Now().Round(time.Second)
	subject := uuid.NewString()
	provider.On("Introspect", ctx, accessToken).Return(&oidc.IntrospectionResponse{
		Active:     true,
		Expiration: oidc.FromTime(tt),
		Subject:    subject,
	}, nil).Once()
	err = authContext.Introspect(ctx, accessToken)
	assert.NoError(t, err)
	assert.Equal(t, accessToken, authContext.Token.AccessToken)
	assert.Equal(t, tt, authContext.Token.Expiry)
	assert.Equal(t, subject, authContext.Subject)
}

func TestAuthContext_Refresh(t *testing.T) {
	ctx := context.Background()
	refreshToken := uuid.NewString()
	provider := mocks.NewProvider(t)

	authContext := &AuthContext{
		Token: oauth2.Token{
			AccessToken: "access-token",
		},
		provider: provider,
	}

	// Error because we miss the Refresh Token
	err := authContext.Refresh(ctx)
	assert.ErrorIs(t, err, ErrBadRequest)

	// Set refresh token and observe the flow
	authContext.Token.RefreshToken = refreshToken
	provider.On("RefreshAccessTokens", ctx, &authContext.Token).Return(nil, ErrBadRequest).Once()
	err = authContext.Refresh(ctx)
	assert.Error(t, err)

	// All good
	accessToken2 := uuid.NewString()
	refreshToken2 := uuid.NewString()
	provider.On("RefreshAccessTokens", ctx, &authContext.Token).Return(&oauth2.Token{
		AccessToken:  accessToken2,
		RefreshToken: refreshToken2,
	}, nil).Once()
	err = authContext.Refresh(ctx)
	assert.NoError(t, err)
	assert.Equal(t, accessToken2, authContext.AccessToken)
	assert.Equal(t, refreshToken2, authContext.RefreshToken)
}

func TestAuthContext_JSON(t *testing.T) {
	authContext := &AuthContext{
		Token: oauth2.Token{
			AccessToken: uuid.NewString(),
			Expiry:      time.Now(),
		},
		UserInfo: oidc.UserInfo{
			Subject: uuid.NewString(),
		},
		Hydrated: true,
	}

	data, err := json.Marshal(authContext)
	require.NoError(t, err)
	assert.NotEmpty(t, data)

	authContext2 := &AuthContext{}
	err = json.Unmarshal(data, authContext2)
	require.NoError(t, err)
	assert.Equal(t, authContext.AccessToken, authContext2.AccessToken)
	assert.Equal(t, authContext.Token.Expiry.Unix(), authContext2.Token.Expiry.Unix())
	assert.Equal(t, authContext.UserInfo.Subject, authContext2.UserInfo.Subject)
	assert.Equal(t, authContext.Hydrated, authContext2.Hydrated)
}
