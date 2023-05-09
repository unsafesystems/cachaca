package oidc

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"google.golang.org/grpc/metadata"

	"github.com/gin-gonic/gin"
	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	gauth "github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/auth"
	"github.com/unsafesystems/cachaca"
	"github.com/unsafesystems/cachaca/auth"
	"github.com/zitadel/oidc/v2/pkg/client/rp"
)

const (
	CookiePrefix        = "cachaca"
	MaxSessionAge       = time.Hour
	SessionKeyBitLength = 512
)

var (
	ErrMissingAuthorizationHeader = errors.New("missing authorization header")
	ErrUnknownIssuer              = errors.New("unknown issuer")
	ErrMissingSessionID           = errors.New("missing session id")
)

type Option interface {
	apply(*Authorizer)
}

type SessionCallbackFunc func(ctx context.Context, session *Session) (interface{}, error)

// Authorizer provides an OAuth/OIDC enabled mechanism for verifying the identity of a user through OAuth and OIDC.
// The authorizer handles the communication and authentication flow with the OAuth/OIDC provider and handles session
// management.
//
// After authentication with the OAuth/OIDC provider and completing the authentication flow, the clients will have to
// provide a bearer token or session cookie which will be used to identify the users. This token/cookie is a short-lived
// JWT with configurable claims. By default, the access token, refresh token and other user information is not stored in
// the session JWT for security reasons. This behaviour can be overridden by providing a custom SessionCallback.
//
// An `oidc.Credentials` object will be passed into the calling context. It provides the claims from the session JWT.
// The information received from the OAuth/OIDC provider (such as the access token) can optionally be stored in a
// pluggable storage interface - and can be lazy-loaded through the provided `oidc.Credentials` object.
type Authorizer struct {
	loginURL        string
	callbackURL     string
	logoutURL       string
	errorURL        string
	successURL      string
	storage         Storage
	provider        map[string]rp.RelyingParty
	issuers         map[string]rp.RelyingParty
	signer          jose.Signer
	signingKey      *jose.SigningKey
	sessionCallback SessionCallbackFunc
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
		issuers:     make(map[string]rp.RelyingParty),
		signer:      signer,
		signingKey:  signingKey,
		sessionCallback: func(ctx context.Context, _ *Session) (interface{}, error) {
			return emptyClaims{}, nil
		},
	}

	for _, opt := range opts {
		opt.apply(authorizer)
	}

	return authorizer
}

// RegisterRelyingParty registers an OAuth/OIDC relying party. The passed name will be used in the login path to
// identify which provider to use. Please note that the issuer string of the relying party must also be unique and
// will be used to validate sessions. Therefore all services consuming the session (JWT) token must have the same
// relying parties configured.
func (authorizer *Authorizer) RegisterRelyingParty(name string, relyingParty rp.RelyingParty) {
	if _, ok := authorizer.provider[name]; ok {
		panic(fmt.Sprintf("relying party %s already registered", name))
	}

	if _, ok := authorizer.issuers[relyingParty.Issuer()]; ok {
		panic(fmt.Sprintf("relying party %s already registered", name))
	}

	// A bit of a design question - but I think a "default" makes sense. The first relying party registered therefore
	// will be accessible under its name - but also on the base path.
	if len(authorizer.provider) == 0 {
		authorizer.provider[""] = relyingParty
	}

	authorizer.provider[name] = relyingParty
	authorizer.issuers[relyingParty.Issuer()] = relyingParty
}

func (authorizer *Authorizer) Apply(server *cachaca.Server) error {
	server.GET(authorizer.loginURL, authorizer.loginHandler)
	server.GET(fmt.Sprintf("%s/*provider", authorizer.loginURL), authorizer.loginHandler)

	server.GET(authorizer.callbackURL, authorizer.callbackHandler)
	server.GET(fmt.Sprintf("%s/*provider", authorizer.callbackURL), authorizer.callbackHandler)

	server.GET(authorizer.logoutURL, authorizer.logoutHandler)

	server.Authorizer = authorizer

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
	state, err := newState(ctx)
	if err != nil {
		_ = ctx.AbortWithError(http.StatusInternalServerError, err)

		return
	}

	err = state.attachState(ctx, authorizer.signer)
	if err != nil {
		_ = ctx.AbortWithError(http.StatusInternalServerError, err)

		return
	}

	// TODS: options for the rp.AuthURL call
	ctx.Redirect(http.StatusFound, rp.AuthURL(state.id, provider))
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

	state, err := validateState(ctx, authorizer.signingKey, ctx.Query("state"))
	if err != nil {
		_ = ctx.AbortWithError(http.StatusUnauthorized, err)

		return
	}

	session, err := NewSessionFromCodeExchange(ctx, ctx.Query("code"), provider)
	if err != nil {
		_ = ctx.AbortWithError(http.StatusUnauthorized, err)

		return
	}

	if authorizer.storage != nil {
		err := authorizer.storage.Set(ctx, session)
		if err != nil {
			_ = ctx.AbortWithError(http.StatusInternalServerError, err)

			return
		}
	}

	token, err := session.generateJWT(ctx, authorizer.signer, authorizer.sessionCallback)
	if err != nil {
		_ = ctx.AbortWithError(http.StatusUnauthorized, err)

		return
	}

	// __Host- prefix according to https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies for increased security
	cookieName := fmt.Sprintf("__Host-%s-session", CookiePrefix)
	if !isHTTPS(ctx) {
		cookieName = fmt.Sprintf("%s-session", CookiePrefix)
	}

	ctx.SetCookie(cookieName, token, 0, "", "", isHTTPS(ctx), true)
	ctx.Header("Authorization", "Bearer "+token)

	state.redirect(ctx, authorizer.successURL)
}

func (authorizer *Authorizer) logoutHandler(ctx *gin.Context) {
	err := authorizer.AuthorizeHTTP(ctx)
	if err != nil {
		ctx.AbortWithStatus(http.StatusUnauthorized)

		return
	}

	creds, ok := auth.GetCredentials[Credentials](ctx)
	if !ok {
		ctx.AbortWithStatus(http.StatusUnauthorized)

		return
	}

	if authorizer.storage != nil {
		err := authorizer.storage.Delete(ctx, creds.ID)
		if err != nil {
			ctx.AbortWithStatus(http.StatusInternalServerError)

			return
		}
	}

	ctx.SetCookie(cookieName(ctx, "session"), "invalid", -1, "", "", isHTTPS(ctx), true)
	ctx.Header("Authorization", "Bearer invalid")
	ctx.Status(http.StatusNoContent)
}

// AuthorizeGrpc implements the `auth.Authorizer` interface and injects the session information into the gRPC context.
func (authorizer *Authorizer) AuthorizeGrpc(ctx context.Context) (context.Context, error) {
	token, err := gauth.AuthFromMD(ctx, "bearer")
	if err != nil {
		return nil, ErrMissingAuthorizationHeader
	}

	oidcCreds, err := authorizer.getCredentialsFromToken(ctx, token)
	if err != nil {
		return nil, err
	}

	// Checks if the token has changed due to e.g. an expiry and adds the header to the outgoing context if necessary
	if oidcCreds.token != token {
		md := metadata.Pairs("authorization", "Bearer "+oidcCreds.token)
		ctx = metadata.NewOutgoingContext(ctx, md)
	}

	return auth.WithCredentials(ctx, oidcCreds), nil
}

// AuthorizeHTTP implements the `auth.Authorizer` interface and injects the session information into the GIN context.
func (authorizer *Authorizer) AuthorizeHTTP(ctx *gin.Context) error {
	var token string

	authHeader := ctx.GetHeader("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		token = strings.TrimPrefix(authHeader, "Bearer ")
	}

	authCookie, err := ctx.Cookie(cookieName(ctx, "session"))
	if err == nil {
		token = authCookie
	}

	if token == "" {
		return ErrMissingAuthorizationHeader
	}

	oidcCreds, err := authorizer.getCredentialsFromToken(ctx, token)
	if err != nil {
		return err
	}

	// Checks if the token has changed due to e.g. an expiry and adds the header to the outgoing context if necessary
	if oidcCreds.token != token {
		ctx.SetCookie(cookieName(ctx, "session"), oidcCreds.token, 0, "", "", isHTTPS(ctx), true)
		ctx.Header("Authorization", "Bearer "+oidcCreds.token)
	}

	auth.WithCredentials(ctx, oidcCreds)

	return nil
}

// getCredentialsFromToken extracts the credentials from the given token and prepares the credentials so it can be
// injected into the calling context. In case the token is expired, it will attempt to refresh the token.
func (authorizer *Authorizer) getCredentialsFromToken(ctx context.Context, token string) (*Credentials, error) {
	claims := new(jwt.Claims)

	err := parseJWT(token, authorizer.signingKey, claims)
	if err != nil {
		return nil, fmt.Errorf("failed to parse claims: %w", err)
	}

	provider, ok := authorizer.issuers[claims.Issuer]
	if !ok {
		return nil, fmt.Errorf("issuer: %s, %w", claims.Issuer, ErrUnknownIssuer)
	}

	// Validate if the claims are still valid
	if err := claims.Validate(jwt.Expected{
		Time: time.Now(),
	}); err == nil {
		return &Credentials{
			Claims:   *claims,
			token:    token,
			storage:  authorizer.storage,
			provider: provider,
		}, nil
	}

	// Not valid and we cannot validate it because we have no storage - we have to fail
	if authorizer.storage == nil {
		return nil, fmt.Errorf("failed to validate claims: %w", err)
	}

	// Attempt to transparently reauthenticate with the OAuth/OIDC provider
	session, err := authorizer.storage.Get(ctx, claims.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to get session: %w", err)
	}

	session.provider = provider

	err = session.refresh(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to refresh session: %w", err)
	}

	token, err = session.generateJWT(ctx, authorizer.signer, authorizer.sessionCallback)
	if err != nil {
		return nil, fmt.Errorf("failed to generate JWT: %w", err)
	}

	err = parseJWT(token, authorizer.signingKey, claims)
	if err != nil {
		return nil, fmt.Errorf("failed to parse claims: %w", err)
	}

	return &Credentials{
		Claims:   *claims,
		token:    token,
		storage:  authorizer.storage,
		provider: provider,
	}, nil
}
