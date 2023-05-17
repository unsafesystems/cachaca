package oidc

import (
	"context"
	"fmt"

	"github.com/zitadel/oidc/v2/pkg/client/rp"
	"github.com/zitadel/oidc/v2/pkg/oidc"
	"golang.org/x/oauth2"
)

//go:generate mockery --name=Provider --filename provider.go
type Provider interface {
	rp.RelyingParty
	Introspect(ctx context.Context, accessToken string) (*oidc.IntrospectionResponse, error)
	RefreshAccessTokens(ctx context.Context, token *oauth2.Token) (*oauth2.Token, error)
	UserInfo(ctx context.Context, token *oauth2.Token) (*oidc.UserInfo, error)
}

type Token struct {
	AccessToken  string
	RefreshToken string
}

type Tokenizer interface {
	Option
	ExchangeCode(ctx context.Context, provider Provider, tokens *oidc.Tokens[*oidc.IDTokenClaims]) (*Token, error)
	Refresh(ctx context.Context, provider Provider, token *Token) (*Token, error)
	ExchangeToken(ctx context.Context, provider Provider, token string) (string, error)
	Authorize(ctx context.Context, provider Provider, token *Token) (*AuthContext, error)
}

type PlainTokenizer struct{}

func NewPlainTokenizer() *PlainTokenizer {
	return &PlainTokenizer{}
}

func (t *PlainTokenizer) Apply(az *Authorizer) {
	az.tokenizer = t
}

func (t *PlainTokenizer) ExchangeCode(_ context.Context, _ Provider, tokens *oidc.Tokens[*oidc.IDTokenClaims],
) (*Token, error) {
	return &Token{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
	}, nil
}

func (t *PlainTokenizer) Refresh(ctx context.Context, provider Provider, token *Token) (*Token, error) {
	authContext := NewAuthContext(provider)
	authContext.Token.RefreshToken = token.RefreshToken

	err := authContext.Refresh(ctx)
	if err != nil {
		return nil, err
	}

	return &Token{
		AccessToken:  authContext.AccessToken,
		RefreshToken: authContext.RefreshToken,
	}, nil
}

func (t *PlainTokenizer) ExchangeToken(_ context.Context, _ Provider, _ string) (string, error) {
	return "", fmt.Errorf("not implemented: %w", ErrBadRequest)
}

func (t *PlainTokenizer) Authorize(ctx context.Context, provider Provider, token *Token) (*AuthContext, error) {
	authContext := NewAuthContext(provider)

	err := authContext.Introspect(ctx, token.AccessToken)
	if err != nil {
		return nil, err
	}

	return authContext, nil
}
