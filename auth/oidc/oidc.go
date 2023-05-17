package oidc

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/rs/zerolog/log"

	"github.com/go-jose/go-jose/v3"
	"github.com/unsafesystems/cachaca"
	"github.com/unsafesystems/cachaca/auth"
	"github.com/unsafesystems/cachaca/auth/oidc/pb"
	"github.com/unsafesystems/cachaca/pkg/pkce"
	"github.com/unsafesystems/cachaca/pkg/secure"
	"github.com/zitadel/oidc/v2/pkg/client/rp"
	"github.com/zitadel/oidc/v2/pkg/oidc"
)

var (
	ErrInternal   = errors.New("internal error")
	ErrBadRequest = errors.New("bad request")
)

type Authorizer struct {
	pb.UnimplementedOIDCServer
	basePath       string
	path           string
	issuer         string
	signingKey     interface{}
	encryptionKey  interface{}
	signer         jose.Signer
	encrypter      jose.Encrypter
	pkceCodeLength int
	stateLength    int
	provider       Provider
	tokenizer      Tokenizer
}

type Option interface {
	Apply(*Authorizer)
}

func NewAuthorizer(provider Provider, opts ...Option) *Authorizer {
	authorizer := &Authorizer{
		provider: provider,
	}

	for _, opt := range opts {
		opt.Apply(authorizer)
	}

	return authorizer
}

func (az *Authorizer) Apply(server *cachaca.Server) error {
	server.GET(az.path+"/login", az.GetAuthURLHTTP)
	server.POST(az.path+"/authorize", az.ExchangeCodeHTTP)
	server.POST(az.path+"/refresh", az.RefreshTokenHTTP)
	server.POST(az.path+"/exchange", az.ExchangeTokenHTTP)

	pb.RegisterOIDCServer(server, az)

	return nil
}

func (az *Authorizer) authURL(ctx interface{}) (string, error) {
	code, err := pkce.Generate(az.pkceCodeLength)
	if err != nil {
		return "", fmt.Errorf("failed to generate pkce verifier: %w: %w", err, ErrInternal)
	}

	state, err := pkce.NewState(az.stateLength, code)
	if err != nil {
		return "", fmt.Errorf("failed to generate state: %w: %w", err, ErrInternal)
	}

	cookieVal, err := state.Marshal(az.issuer, az.signer, az.encrypter)
	if err != nil {
		log.Err(err).Msg("failed to marshal state")

		return "", fmt.Errorf("failed to marshal state: %w: %w", err, ErrInternal)
	}

	secure.SetCookie(ctx, "/", "state", cookieVal)

	return rp.AuthURL(state.State(), az.provider, code.Challenge), nil
}

func (az *Authorizer) exchangeCode(ctx interface{}, req *pb.ExchangeCodeRequest) error {
	cookie, ok := secure.GetCookie(ctx, "state")
	if !ok {
		return fmt.Errorf("failed to get state cookie: %w", ErrBadRequest)
	}

	secure.DeleteCookie(ctx, "/", "state")

	pkceCode, err := pkce.Validate(cookie, req.State, az.issuer, az.signingKey, az.encryptionKey)
	if err != nil {
		return fmt.Errorf("failed to validate state: %w: %w", err, ErrBadRequest)
	}

	tokens, err := rp.CodeExchange[*oidc.IDTokenClaims](ctx.(context.Context), req.Code, az.provider, pkceCode.Verifier)
	if err != nil {
		return fmt.Errorf("failed to exchange code: %w: %w", err, ErrInternal)
	}

	token, err := az.tokenizer.ExchangeCode(ctx.(context.Context), az.provider, tokens)
	if err != nil {
		return fmt.Errorf("failed to exchange code: %w: %w", err, ErrInternal)
	}

	az.setToken(ctx, token)

	return nil
}

func (az *Authorizer) refreshToken(ctx interface{}) error {
	token := newTokenFromContext(ctx)

	token, err := az.tokenizer.Refresh(ctx.(context.Context), az.provider, token)
	if err != nil {
		return fmt.Errorf("failed to refresh token: %w: %w", err, ErrInternal)
	}

	az.setToken(ctx, token)

	return nil
}

func (az *Authorizer) exchangeToken(ctx context.Context, req *pb.ExchangeTokenRequest,
) (*pb.ExchangeTokenResponse, error) {
	token, err := az.tokenizer.ExchangeToken(ctx, az.provider, req.Token)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange token: %w: %w", err, ErrInternal)
	}

	return &pb.ExchangeTokenResponse{
		Token: token,
	}, nil
}

func (az *Authorizer) setToken(ctx interface{}, token *Token) {
	if token == nil {
		return
	}

	secure.SetCookie(ctx, "", "authorization", token.AccessToken)

	if token.RefreshToken != "" {
		path := fmt.Sprintf("%s%s/refresh", az.basePath, az.path)
		secure.SetCookie(ctx, path, "refresh_token", token.RefreshToken)

		// grpc-web has a different path
		secure.SetCookie(ctx, "/cachaca.authentication.v1.OIDC/RefreshToken", "refresh_token", token.RefreshToken)
	}
}

func newTokenFromContext(req interface{}) *Token {
	token := new(Token)

	val, ok := secure.GetHeader(req, "authorization")
	if ok {
		tk := strings.Split(val, " ")
		if len(tk) == 2 && strings.EqualFold(tk[0], "Bearer") {
			token.AccessToken = tk[1]
		}

		return token
	}

	val, ok = secure.GetCookie(req, "authorization")
	if ok {
		token.AccessToken = val
	}

	val, ok = secure.GetCookie(req, "refresh_token")
	if ok {
		token.RefreshToken = val
	}

	return token
}

func (az *Authorizer) Authorize(ctx interface{}) (context.Context, error) {
	if ctx == nil {
		return nil, fmt.Errorf("context not provided: %w", ErrInternal)
	}

	token := newTokenFromContext(ctx)

	authContext, err := az.tokenizer.Authorize(ctx.(context.Context), az.provider, token)
	if err != nil {
		return nil, fmt.Errorf("authorization failed: %w: %w", err, ErrBadRequest)
	}

	return auth.WithCredentials(ctx, authContext), nil
}
