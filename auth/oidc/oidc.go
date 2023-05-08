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

type Credentials struct {
	// tokens *oidc.Tokens[*oidc.IDTokenClaims]
}

type Option interface {
	apply(*Authorizer)
}

type TokenCallback func(tokens *oidc.Tokens[*oidc.IDTokenClaims], userInfo *oidc.UserInfo) (interface{}, error)

type Authorizer struct {
	loginURL      string
	callbackURL   string
	logoutURL     string
	errorURL      string
	successURL    string
	storage       Storage
	provider      map[string]rp.RelyingParty
	signer        jose.Signer
	signingKey    *jose.SigningKey
	tokenCallback TokenCallback
}

type emptyClaims struct{}

func NewAuthorizer(signingKey *jose.SigningKey, opts ...Option) *Authorizer {
	signer, err := jose.NewSigner(*signingKey, nil)
	if err != nil {
		panic(err)
	}

	authorizer := &Authorizer{
		loginURL:    "/oidc/login",
		callbackURL: "/oidc/authorize",
		logoutURL:   "/oidc/logout",
		errorURL:    "/oidc/error",
		successURL:  "/oidc/success",
		provider:    make(map[string]rp.RelyingParty),
		signer:      signer,
		signingKey:  signingKey,
		tokenCallback: func(tokens *oidc.Tokens[*oidc.IDTokenClaims], userInfo *oidc.UserInfo) (interface{}, error) {
			return emptyClaims{}, nil
		},
	}

	for _, opt := range opts {
		opt.apply(authorizer)
	}

	return authorizer
}

func (authorizer *Authorizer) RegisterRelyingParty(name string, relyingParty rp.RelyingParty) {
	if _, ok := authorizer.provider[name]; ok {
		panic(fmt.Sprintf("relying party %s already registered", name))
	}

	// A bit of a design question - but I think a "default" makes sense. The first relying party registered therefore
	// will be accessible under its name - but also on the base path.
	if len(authorizer.provider) == 0 {
		authorizer.provider[""] = relyingParty
	}

	authorizer.provider[name] = relyingParty
}

func (authorizer *Authorizer) Apply(server *cachaca.Server) error {
	server.GET(authorizer.loginURL, authorizer.loginHandler)
	server.GET(fmt.Sprintf("%s/*provider", authorizer.loginURL), authorizer.loginHandler)

	server.GET(authorizer.callbackURL, authorizer.callbackHandler)
	server.GET(fmt.Sprintf("%s/*provider", authorizer.callbackURL), authorizer.callbackHandler)

	server.GET(authorizer.logoutURL, authorizer.logoutHandler)

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
		ctx.AbortWithStatus(http.StatusInternalServerError)
		ctx.JSON(-1, gin.H{"error": err.Error()})

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

	if ctx.Query("error") != "" {
		query := ctx.Request.URL.Query().Encode()
		ctx.Redirect(http.StatusFound, authorizer.errorURL+"?"+query)

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

	claims, err := authorizer.tokenCallback(tokens, userInfo)
	if err != nil {
		_ = ctx.AbortWithError(http.StatusInternalServerError, err)

		return
	}

	sessionKey, err := setSessionCookie(ctx, tokens, authorizer.signer, claims)
	if err != nil {
		_ = ctx.AbortWithError(http.StatusInternalServerError, err)

		return
	}

	if authorizer.storage != nil {
		err := authorizer.storage.Set(ctx, sessionKey, tokens)
		if err != nil {
			_ = ctx.AbortWithError(http.StatusInternalServerError, err)

			return
		}
	}

	redirectFromStateCookie(ctx, stateClaims, authorizer.successURL)
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

func (authorizer *Authorizer) logoutHandler(_ *gin.Context) {
	panic("implement me")
}

func (authorizer *Authorizer) AuthorizeGrpc(_ context.Context, _ *auth.Credentials) (context.Context, error) {
	panic("implement me")
}

func (authorizer *Authorizer) AuthorizeHTTP(_ *gin.Context, _ *auth.Credentials) error {
	panic("implement me")
}
