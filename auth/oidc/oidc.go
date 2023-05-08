package oidc

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/go-jose/go-jose/v3"
	"github.com/zitadel/oidc/v2/pkg/client/rp"
	"github.com/zitadel/oidc/v2/pkg/oidc"

	"github.com/gin-gonic/gin"
	"github.com/unsafesystems/cachaca"
	"github.com/unsafesystems/cachaca/auth"
)

const (
	cookiePrefix = "cachaca"
)

type (
	ErrorHandler         func(ctx *gin.Context, errorType string, errorDesc string, state string)
	CodeExchangeCallback func(ctx context.Context, tokens *oidc.Tokens[*oidc.IDTokenClaims],
		userInfo *oidc.UserInfo, rp rp.RelyingParty) (interface{}, error)
)

type RelyingParty struct {
	rp.RelyingParty
	name string
}

func NewRelyingParty(name string, relyingParty rp.RelyingParty) RelyingParty {
	return RelyingParty{
		RelyingParty: relyingParty,
		name:         name,
	}
}

func DefaultCodeExchangeCallback(_ context.Context, _ *oidc.Tokens[*oidc.IDTokenClaims],
	userInfo *oidc.UserInfo, _ rp.RelyingParty,
) (interface{}, error) {
	return userInfo, nil
}

type Authorizer struct {
	loginURL           string
	callbackURL        string
	defaultRedirectURL string
	errorHandler       ErrorHandler
	provider           map[string]rp.RelyingParty
	signer             jose.Signer
	callback           CodeExchangeCallback
	signingKey         *jose.SigningKey
}

func NewAuthorizer(signingKey *jose.SigningKey, rps ...RelyingParty) *Authorizer {
	if len(rps) == 0 {
		panic("no relying parties provided")
	}

	signer, err := jose.NewSigner(*signingKey, nil)
	if err != nil {
		panic(err)
	}

	authorizer := &Authorizer{
		loginURL:           "/oidc/login",
		callbackURL:        "/oidc/authorize",
		defaultRedirectURL: "/",
		provider:           make(map[string]rp.RelyingParty),
		callback:           DefaultCodeExchangeCallback,
		signer:             signer,
		signingKey:         signingKey,
	}

	authorizer.provider[""] = rps[0]

	for _, relyingParty := range rps {
		authorizer.provider[relyingParty.name] = relyingParty
	}

	return authorizer
}

func (authorizer *Authorizer) Apply(server *cachaca.Server) error {
	server.GET(authorizer.loginURL, authorizer.loginHandler)
	server.GET(fmt.Sprintf("%s/*provider", authorizer.loginURL), authorizer.loginHandler)
	server.GET(authorizer.callbackURL, authorizer.callbackHandler)
	server.GET(fmt.Sprintf("%s/*provider", authorizer.callbackURL), authorizer.callbackHandler)

	return nil
}

// loginHandler builds the auth url and redirects the user to the provider login page. For CSRF protection it handles
// secure state cookie generation - which can also be used to store a redirect url.
func (authorizer *Authorizer) loginHandler(ctx *gin.Context) {
	providerName := strings.Trim(ctx.Param("provider"), "/ ")

	provider, ok := authorizer.provider[providerName]
	if !ok {
		ctx.AbortWithStatus(http.StatusNotFound)

		return
	}

	// State is used primarily to combat CSRF attacks, but can also be used to maintain a state before login - such as
	// remembering the page the user was on.
	state, err := setStateCookie(ctx, authorizer.signer)
	if err != nil {
		_ = ctx.AbortWithError(http.StatusInternalServerError, err)

		return
	}

	// TODS: options for the rp.AuthURL call
	ctx.Redirect(http.StatusFound, rp.AuthURL(state, provider))
}

func (authorizer *Authorizer) callbackHandler(ctx *gin.Context) {
	providerName := ctx.Param("provider")

	provider, ok := authorizer.provider[providerName]
	if !ok {
		ctx.AbortWithStatus(http.StatusNotFound)

		return
	}

	if ctx.Param("error") != "" {
		errorType := ctx.Param("error")
		errorDesc := ctx.Param("error_description")
		state := ctx.Param("state")

		authorizer.errorHandler(ctx, errorType, errorDesc, state)

		return
	}

	stateClaims, err := validateStateCookie(ctx, authorizer.signingKey, ctx.Query("state"))
	if err != nil {
		_ = ctx.AbortWithError(http.StatusUnauthorized, err)

		return
	}

	tokens, userInfo, err := exchangeToken(ctx, provider)
	if err != nil {
		_ = ctx.AbortWithError(http.StatusUnauthorized, err)

		return
	}

	claims, err := authorizer.callback(ctx, tokens, userInfo, provider)
	if err != nil {
		_ = ctx.AbortWithError(http.StatusInternalServerError, err)

		return
	}

	err = setSessionCookie(ctx, tokens, authorizer.signer, claims)
	if err != nil {
		_ = ctx.AbortWithError(http.StatusInternalServerError, err)

		return
	}

	redirectFromStateCookie(ctx, stateClaims, authorizer.defaultRedirectURL)
}

func exchangeToken(ctx *gin.Context, provider rp.RelyingParty) (*oidc.Tokens[*oidc.IDTokenClaims],
	*oidc.UserInfo, error,
) {
	// TODS: CodeExchangeOpts
	tokens, err := rp.CodeExchange[*oidc.IDTokenClaims](ctx, ctx.Query("code"), provider)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to exchange token: %w", err)
	}

	var userInfo *oidc.UserInfo

	if !provider.IsOAuth2Only() {
		// Not sure which servers have this problem. At least the mockoidc server does not return the correct type for
		// the token_type field.
		tokenType := tokens.TokenType
		if tokenType == "bearer" {
			tokenType = "Bearer"
		}

		userInfo, err = rp.Userinfo(tokens.AccessToken, tokenType, tokens.IDTokenClaims.GetSubject(), provider)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get userinfo: %w", err)
		}
	}

	return tokens, userInfo, nil
}

func (authorizer *Authorizer) AuthorizeGrpc(_ context.Context, _ *auth.Credentials) (context.Context, error) {
	panic("implement me")
}

func (authorizer *Authorizer) AuthorizeHTTP(_ *gin.Context, _ *auth.Credentials) error {
	panic("implement me")
}
