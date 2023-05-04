//nolint
package cachaca

import (
	"context"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/unsafesystems/cachaca/auth"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	jwtKeyFunc = func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// hmacSampleSecret is a []byte containing your secret, e.g. []byte("my_secret_key")
		return []byte("secret"), nil
	}
	jwtToken = &jwt.RegisteredClaims{}
)

func TestAuthentication_Unauthenticated(t *testing.T) {
	middleware := NewAuthenticationMiddleware(jwtKeyFunc, jwtToken)
	ctx := context.Background()
	ctx, err := middleware.Middleware(ctx)
	assert.Nil(t, ctx)
	require.NotNil(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}

func TestAuthentication_TokenSuccess(t *testing.T) {
	id := uuid.NewString()
	audience := uuid.NewString()

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Issuer:    "",
		Subject:   "",
		Audience:  []string{audience},
		ExpiresAt: nil,
		NotBefore: nil,
		IssuedAt:  nil,
		ID:        id,
	})
	tokenString, err := token.SignedString([]byte("secret"))
	require.Nil(t, err)

	middleware := NewAuthenticationMiddleware(jwtKeyFunc, jwtToken)
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", fmt.Sprintf("Bearer %s", tokenString)))

	ctx, err = middleware.Middleware(ctx)
	require.NotNil(t, ctx)
	assert.Nil(t, err)

	authContext, ok := ctx.Value(auth.AuthenticationKey{}).(auth.Authentication)
	require.True(t, ok)

	tokenClaims := authContext.Token.(*jwt.RegisteredClaims)
	assert.Equal(t, id, tokenClaims.ID)
	assert.Equal(t, audience, tokenClaims.Audience[0])
}

type CustomClaims struct {
	jwt.RegisteredClaims
	Role string `json:"role"`
}

func TestAuthentication_CustomToken(t *testing.T) {
	id := uuid.NewString()
	audience := uuid.NewString()

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, CustomClaims{
		jwt.RegisteredClaims{
			Issuer:    "",
			Subject:   "",
			Audience:  []string{audience},
			ExpiresAt: nil,
			NotBefore: nil,
			IssuedAt:  nil,
			ID:        id,
		},
		"admin",
	})
	tokenString, err := token.SignedString([]byte("secret"))
	require.Nil(t, err)

	middleware := NewAuthenticationMiddleware(jwtKeyFunc, &CustomClaims{})
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", fmt.Sprintf("Bearer %s", tokenString)))

	ctx, err = middleware.Middleware(ctx)
	require.NotNil(t, ctx)
	assert.Nil(t, err)

	authContext, ok := ctx.Value(auth.AuthenticationKey{}).(auth.Authentication)
	require.True(t, ok)

	tokenClaims := authContext.Token.(*CustomClaims)
	assert.Equal(t, id, tokenClaims.ID)
	assert.Equal(t, audience, tokenClaims.Audience[0])
	assert.Equal(t, "admin", tokenClaims.Role)
}

func TestAuthentication_InvalidToken(t *testing.T) {
	id := uuid.NewString()
	audience := uuid.NewString()

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Issuer:    "",
		Subject:   "",
		Audience:  []string{audience},
		ExpiresAt: nil,
		NotBefore: nil,
		IssuedAt:  nil,
		ID:        id,
	})
	tokenString, err := token.SignedString([]byte("secret123"))
	require.Nil(t, err)

	middleware := NewAuthenticationMiddleware(jwtKeyFunc, jwtToken)
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", fmt.Sprintf("Bearer %s", tokenString)))

	_, err = middleware.Middleware(ctx)
	require.NotNil(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}
