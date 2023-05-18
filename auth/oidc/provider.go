package oidc

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/zitadel/oidc/v2/pkg/client"
	"github.com/zitadel/oidc/v2/pkg/client/rp"
	"github.com/zitadel/oidc/v2/pkg/client/rs"
	httphelper "github.com/zitadel/oidc/v2/pkg/http"
	"github.com/zitadel/oidc/v2/pkg/oidc"
	"golang.org/x/oauth2"
)

//go:generate mockery --name=Provider --filename provider.go
type Provider interface {
	rp.RelyingParty
	Introspect(ctx context.Context, accessToken string) (*oidc.IntrospectionResponse, error)
	RefreshAccessTokens(ctx context.Context, token *oauth2.Token) (*oauth2.Token, error)
	UserInfo(ctx context.Context, subject string, token *oauth2.Token) (*oidc.UserInfo, error)
}

type BaseProvider struct {
	rp.RelyingParty
	rs.ResourceServer
}

func NewBaseProvider(rp rp.RelyingParty, rs rs.ResourceServer) *BaseProvider {
	return &BaseProvider{
		RelyingParty:   rp,
		ResourceServer: rs,
	}
}

func (p *BaseProvider) Introspect(ctx context.Context, accessToken string) (*oidc.IntrospectionResponse, error) {
	res, err := rs.Introspect(ctx, p.ResourceServer, accessToken)
	if err != nil {
		return nil, fmt.Errorf("introspect failed: %w", err)
	}

	return res, nil
}

type tokenEndpointCaller struct {
	rp.RelyingParty
}

func (t tokenEndpointCaller) TokenEndpoint() string {
	return t.OAuthConfig().Endpoint.TokenURL
}

func (p *BaseProvider) RefreshAccessTokens(_ context.Context, token *oauth2.Token) (*oauth2.Token, error) {
	request := rp.RefreshTokenRequest{
		RefreshToken:        token.RefreshToken,
		Scopes:              p.OAuthConfig().Scopes,
		ClientID:            p.OAuthConfig().ClientID,
		ClientSecret:        p.OAuthConfig().ClientSecret,
		ClientAssertion:     "",
		ClientAssertionType: "",
		GrantType:           oidc.GrantTypeRefreshToken,
	}

	res, err := client.CallTokenEndpoint(request, tokenEndpointCaller{RelyingParty: p.RelyingParty})
	if err != nil {
		return nil, fmt.Errorf("failed to refresh access token: %w", err)
	}

	return res, nil
}

func (p *BaseProvider) UserInfo(ctx context.Context, subject string, token *oauth2.Token) (*oidc.UserInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.UserinfoEndpoint(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create userinfo request: %w", err)
	}

	if token.TokenType == "bearer" {
		token.TokenType = "Bearer"
	}

	req.Header.Set("authorization", http.CanonicalHeaderKey(token.TokenType)+" "+token.AccessToken)

	userinfo := new(oidc.UserInfo)
	if err := httphelper.HttpRequest(p.RelyingParty.HttpClient(), req, &userinfo); err != nil {
		return nil, fmt.Errorf("failed to get userinfo: %w", err)
	}

	if subject != "" && userinfo.Subject != subject {
		return nil, fmt.Errorf("userinfo subject mismatch: %w", ErrBadRequest)
	}

	return userinfo, nil
}

type CachingProvider struct {
	BaseProvider
	cache  Cache
	maxTTL time.Duration
}

func NewCachingProvider(rp rp.RelyingParty, rs rs.ResourceServer, cache Cache, maxTTL time.Duration,
) *CachingProvider {
	return &CachingProvider{
		BaseProvider: BaseProvider{
			RelyingParty:   rp,
			ResourceServer: rs,
		},
		cache:  cache,
		maxTTL: maxTTL,
	}
}

func (p *CachingProvider) Introspect(ctx context.Context, accessToken string) (*oidc.IntrospectionResponse, error) {
	return wrapFunctionForCache(ctx, accessToken, p.cache, func() (*oidc.IntrospectionResponse, time.Duration, error) {
		res, err := p.BaseProvider.Introspect(ctx, accessToken)
		if err != nil {
			return nil, 0, err
		}

		return res, limitExpiration(res.Expiration.AsTime(), p.maxTTL), nil
	})
}

func (p *CachingProvider) UserInfo(ctx context.Context, subject string, token *oauth2.Token) (*oidc.UserInfo, error) {
	return wrapFunctionForCache(ctx, subject, p.cache, func() (*oidc.UserInfo, time.Duration, error) {
		res, err := p.BaseProvider.UserInfo(ctx, subject, token)
		if err != nil {
			return nil, 0, err
		}

		return res, p.maxTTL, nil
	})
}

func limitExpiration(expiration time.Time, maxTTL time.Duration) time.Duration {
	if expiration.IsZero() {
		return time.Duration(0)
	}

	if time.Until(expiration) > maxTTL {
		return maxTTL
	}

	return time.Until(expiration)
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
