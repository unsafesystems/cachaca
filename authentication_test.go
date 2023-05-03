//nolint
package cachaca

import (
	"context"
	"fmt"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"testing"

	"github.com/dgrijalva/jwt-go"
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
	jwtToken = &jwt.StandardClaims{}
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

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.StandardClaims{
		Audience:  audience,
		ExpiresAt: 0,
		Id:        id,
		IssuedAt:  0,
		Issuer:    "",
		NotBefore: 0,
		Subject:   "",
	})
	tokenString, err := token.SignedString([]byte("secret"))
	require.Nil(t, err)

	middleware := NewAuthenticationMiddleware(jwtKeyFunc, jwtToken)
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", fmt.Sprintf("Bearer %s", tokenString)))

	ctx, err = middleware.Middleware(ctx)
	require.NotNil(t, ctx)
	assert.Nil(t, err)

	authContext, ok := ctx.Value(AuthenticationKey{}).(Authentication)
	require.True(t, ok)

	tokenClaims := authContext.Token.(*jwt.StandardClaims)
	assert.Equal(t, id, tokenClaims.Id)
	assert.Equal(t, audience, tokenClaims.Audience)
}

type CustomClaims struct {
	jwt.StandardClaims
	Role string `json:"role"`
}

func TestAuthentication_CustomToken(t *testing.T) {
	id := uuid.NewString()
	audience := uuid.NewString()

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, CustomClaims{
		jwt.StandardClaims{
			Audience:  audience,
			ExpiresAt: 0,
			Id:        id,
			IssuedAt:  0,
			Issuer:    "",
			NotBefore: 0,
			Subject:   "",
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

	authContext, ok := ctx.Value(AuthenticationKey{}).(Authentication)
	require.True(t, ok)

	tokenClaims := authContext.Token.(*CustomClaims)
	assert.Equal(t, id, tokenClaims.Id)
	assert.Equal(t, audience, tokenClaims.Audience)
	assert.Equal(t, "admin", tokenClaims.Role)
}

func TestAuthentication_InvalidToken(t *testing.T) {
	id := uuid.NewString()
	audience := uuid.NewString()

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.StandardClaims{
		Audience:  audience,
		ExpiresAt: 0,
		Id:        id,
		IssuedAt:  0,
		Issuer:    "",
		NotBefore: 0,
		Subject:   "",
	})
	tokenString, err := token.SignedString([]byte("secret123"))
	require.Nil(t, err)

	middleware := NewAuthenticationMiddleware(jwtKeyFunc, jwtToken)
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", fmt.Sprintf("Bearer %s", tokenString)))

	_, err = middleware.Middleware(ctx)
	require.NotNil(t, err)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
}
