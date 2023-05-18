package oidc

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/zitadel/oidc/v2/pkg/oidc"
	"golang.org/x/oauth2"
)

const (
	MinSessionAge = 5 * time.Minute
	MaxSessionAge = time.Hour
)

type AuthContext struct {
	oidc.UserInfo
	oauth2.Token
	Hydrated bool `json:"hydrated,omitempty"`

	provider Provider
	nowF     func() time.Time
}

func NewAuthContext(provider Provider) *AuthContext {
	return &AuthContext{
		provider: provider,
		Hydrated: false,
	}
}

// Hydrate will attempt to load the user information from the provider. If the AuthContext is already hydrated this
// method will be a no-op.
func (ac *AuthContext) Hydrate(ctx context.Context) error {
	if ac.Hydrated {
		return nil
	}

	return ac.LoadUserInfo(ctx)
}

// Refresh will refresh the access token using the refresh token. The refresh token must be set in the AuthContext.
func (ac *AuthContext) Refresh(ctx context.Context) error {
	if ac.RefreshToken == "" {
		return fmt.Errorf("missing refresh token: %w", ErrBadRequest)
	}

	// Update access and refresh tokens
	tokens, err := ac.provider.RefreshAccessTokens(ctx, &ac.Token)
	if err != nil {
		return fmt.Errorf("failed to refresh using access token: %w: %w", err, ErrBadRequest)
	}

	ac.Token = *tokens

	return nil
}

// Expiry returns the expected expiry of the access token. Expiry is limited to a maximum of 1 hour.
func (ac *AuthContext) Expiry() time.Time {
	return ac.Token.Expiry
}

// LoadUserInfo will load the user information from the provider. The data of the AuthContext will be overwritten with
// the user information.
func (ac *AuthContext) LoadUserInfo(ctx context.Context) error {
	if ac.provider == nil {
		return fmt.Errorf("missing provider: %w", ErrInternal)
	}

	if ac.AccessToken == "" {
		return fmt.Errorf("missing access token: %w", ErrBadRequest)
	}

	userInfo, err := ac.provider.UserInfo(ctx, ac.Subject, &ac.Token)
	if err != nil {
		return fmt.Errorf("failed to load user info: %w: %w", err, ErrBadRequest)
	}

	ac.UserInfo = *userInfo
	ac.Hydrated = true

	return nil
}

// Introspect will introspect the access token and validate its validity by calling the introspection endpoint of the
// provider. The data of the AuthContext will be overwritten with the introspection information. In case no AccessToken
// is provided, the access token from the AuthContext will be reused.
func (ac *AuthContext) Introspect(ctx context.Context, accessToken string) error {
	if ac.provider == nil {
		return fmt.Errorf("missing provider: %w", ErrInternal)
	}

	if accessToken == "" {
		accessToken = ac.AccessToken
	}

	introspection, err := ac.provider.Introspect(ctx, accessToken)
	if err != nil {
		return fmt.Errorf("failed to introspect access token: %w: %w", err, ErrBadRequest)
	}

	if !introspection.Active {
		return fmt.Errorf("access token not active: %w", ErrBadRequest)
	}

	if introspection.Expiration.AsTime().IsZero() {
		ac.updateExpiry(ac.now().Add(MinSessionAge))
	} else {
		ac.updateExpiry(introspection.Expiration.AsTime())
	}

	ac.AccessToken = accessToken
	ac.Subject = introspection.Subject
	ac.UserInfo.UserInfoProfile = introspection.UserInfoProfile
	ac.UserInfo.UserInfoEmail = introspection.UserInfoEmail
	ac.UserInfo.UserInfoPhone = introspection.UserInfoPhone
	ac.UserInfo.Address = introspection.Address
	ac.UserInfo.Claims = introspection.Claims
	ac.Hydrated = false

	return nil
}

func (ac *AuthContext) updateExpiry(expiry time.Time) {
	if expiry.IsZero() {
		return
	}

	if time.Until(expiry) > MaxSessionAge {
		expiry = ac.now().Add(MaxSessionAge)
	}

	ac.Token.Expiry = expiry
}

func (ac *AuthContext) now() time.Time {
	if ac.nowF != nil {
		return ac.nowF()
	}

	return time.Now()
}

func (ac *AuthContext) MarshalJSON() ([]byte, error) {
	buf := new(bytes.Buffer)

	tmp := make(map[string]interface{})
	tmp["hydrated"] = ac.Hydrated

	err := json.NewEncoder(buf).Encode(&ac.Token)
	if err != nil {
		return nil, fmt.Errorf("authContext marshal failed: %w", err)
	}

	err = json.NewDecoder(buf).Decode(&tmp)
	if err != nil {
		return nil, fmt.Errorf("authContext marshal failed: %w", err)
	}

	err = json.NewEncoder(buf).Encode(&ac.UserInfo)
	if err != nil {
		return nil, fmt.Errorf("authContext marshal failed: %w", err)
	}

	err = json.NewDecoder(buf).Decode(&tmp)
	if err != nil {
		return nil, fmt.Errorf("authContext marshal failed: %w", err)
	}

	res, err := json.Marshal(tmp)
	if err != nil {
		return nil, fmt.Errorf("authContext marshal failed: %w", err)
	}

	return res, nil
}

func (ac *AuthContext) UnmarshalJSON(data []byte) error {
	err := json.Unmarshal(data, &ac.UserInfo)
	if err != nil {
		return fmt.Errorf("authContext unmarshal failed: %w", err)
	}

	err = json.Unmarshal(data, &ac.Token)
	if err != nil {
		return fmt.Errorf("authContext unmarshal failed: %w", err)
	}

	type hydrated struct {
		Hydrated bool `json:"hydrated,omitempty"`
	}

	hyd := new(hydrated)

	err = json.Unmarshal(data, &hyd)
	if err != nil {
		return fmt.Errorf("authContext unmarshal failed: %w", err)
	}

	ac.Hydrated = hyd.Hydrated

	return nil
}
