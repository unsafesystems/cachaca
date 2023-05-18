// Code generated by mockery v2.23.2. DO NOT EDIT.

package mocks

import (
	context "context"

	http "github.com/zitadel/oidc/v2/pkg/http"
	jose "gopkg.in/square/go-jose.v2"

	mock "github.com/stretchr/testify/mock"

	nethttp "net/http"

	oauth2 "golang.org/x/oauth2"

	pkgoidc "github.com/zitadel/oidc/v2/pkg/oidc"

	rp "github.com/zitadel/oidc/v2/pkg/client/rp"
)

// Provider is an autogenerated mock type for the Provider type
type Provider struct {
	mock.Mock
}

// CookieHandler provides a mock function with given fields:
func (_m *Provider) CookieHandler() *http.CookieHandler {
	ret := _m.Called()

	var r0 *http.CookieHandler
	if rf, ok := ret.Get(0).(func() *http.CookieHandler); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*http.CookieHandler)
		}
	}

	return r0
}

// ErrorHandler provides a mock function with given fields:
func (_m *Provider) ErrorHandler() func(nethttp.ResponseWriter, *nethttp.Request, string, string, string) {
	ret := _m.Called()

	var r0 func(nethttp.ResponseWriter, *nethttp.Request, string, string, string)
	if rf, ok := ret.Get(0).(func() func(nethttp.ResponseWriter, *nethttp.Request, string, string, string)); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(func(nethttp.ResponseWriter, *nethttp.Request, string, string, string))
		}
	}

	return r0
}

// GetDeviceAuthorizationEndpoint provides a mock function with given fields:
func (_m *Provider) GetDeviceAuthorizationEndpoint() string {
	ret := _m.Called()

	var r0 string
	if rf, ok := ret.Get(0).(func() string); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(string)
	}

	return r0
}

// GetEndSessionEndpoint provides a mock function with given fields:
func (_m *Provider) GetEndSessionEndpoint() string {
	ret := _m.Called()

	var r0 string
	if rf, ok := ret.Get(0).(func() string); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(string)
	}

	return r0
}

// GetRevokeEndpoint provides a mock function with given fields:
func (_m *Provider) GetRevokeEndpoint() string {
	ret := _m.Called()

	var r0 string
	if rf, ok := ret.Get(0).(func() string); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(string)
	}

	return r0
}

// HttpClient provides a mock function with given fields:
func (_m *Provider) HttpClient() *nethttp.Client {
	ret := _m.Called()

	var r0 *nethttp.Client
	if rf, ok := ret.Get(0).(func() *nethttp.Client); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*nethttp.Client)
		}
	}

	return r0
}

// IDTokenVerifier provides a mock function with given fields:
func (_m *Provider) IDTokenVerifier() rp.IDTokenVerifier {
	ret := _m.Called()

	var r0 rp.IDTokenVerifier
	if rf, ok := ret.Get(0).(func() rp.IDTokenVerifier); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(rp.IDTokenVerifier)
		}
	}

	return r0
}

// Introspect provides a mock function with given fields: ctx, accessToken
func (_m *Provider) Introspect(ctx context.Context, accessToken string) (*pkgoidc.IntrospectionResponse, error) {
	ret := _m.Called(ctx, accessToken)

	var r0 *pkgoidc.IntrospectionResponse
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string) (*pkgoidc.IntrospectionResponse, error)); ok {
		return rf(ctx, accessToken)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string) *pkgoidc.IntrospectionResponse); ok {
		r0 = rf(ctx, accessToken)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*pkgoidc.IntrospectionResponse)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, string) error); ok {
		r1 = rf(ctx, accessToken)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// IsOAuth2Only provides a mock function with given fields:
func (_m *Provider) IsOAuth2Only() bool {
	ret := _m.Called()

	var r0 bool
	if rf, ok := ret.Get(0).(func() bool); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(bool)
	}

	return r0
}

// IsPKCE provides a mock function with given fields:
func (_m *Provider) IsPKCE() bool {
	ret := _m.Called()

	var r0 bool
	if rf, ok := ret.Get(0).(func() bool); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(bool)
	}

	return r0
}

// Issuer provides a mock function with given fields:
func (_m *Provider) Issuer() string {
	ret := _m.Called()

	var r0 string
	if rf, ok := ret.Get(0).(func() string); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(string)
	}

	return r0
}

// OAuthConfig provides a mock function with given fields:
func (_m *Provider) OAuthConfig() *oauth2.Config {
	ret := _m.Called()

	var r0 *oauth2.Config
	if rf, ok := ret.Get(0).(func() *oauth2.Config); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*oauth2.Config)
		}
	}

	return r0
}

// RefreshAccessTokens provides a mock function with given fields: ctx, token
func (_m *Provider) RefreshAccessTokens(ctx context.Context, token *oauth2.Token) (*oauth2.Token, error) {
	ret := _m.Called(ctx, token)

	var r0 *oauth2.Token
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, *oauth2.Token) (*oauth2.Token, error)); ok {
		return rf(ctx, token)
	}
	if rf, ok := ret.Get(0).(func(context.Context, *oauth2.Token) *oauth2.Token); ok {
		r0 = rf(ctx, token)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*oauth2.Token)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, *oauth2.Token) error); ok {
		r1 = rf(ctx, token)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Signer provides a mock function with given fields:
func (_m *Provider) Signer() jose.Signer {
	ret := _m.Called()

	var r0 jose.Signer
	if rf, ok := ret.Get(0).(func() jose.Signer); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(jose.Signer)
		}
	}

	return r0
}

// UserInfo provides a mock function with given fields: ctx, subject, token
func (_m *Provider) UserInfo(ctx context.Context, subject string, token *oauth2.Token) (*pkgoidc.UserInfo, error) {
	ret := _m.Called(ctx, subject, token)

	var r0 *pkgoidc.UserInfo
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context, string, *oauth2.Token) (*pkgoidc.UserInfo, error)); ok {
		return rf(ctx, subject, token)
	}
	if rf, ok := ret.Get(0).(func(context.Context, string, *oauth2.Token) *pkgoidc.UserInfo); ok {
		r0 = rf(ctx, subject, token)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*pkgoidc.UserInfo)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context, string, *oauth2.Token) error); ok {
		r1 = rf(ctx, subject, token)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// UserinfoEndpoint provides a mock function with given fields:
func (_m *Provider) UserinfoEndpoint() string {
	ret := _m.Called()

	var r0 string
	if rf, ok := ret.Get(0).(func() string); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(string)
	}

	return r0
}

type mockConstructorTestingTNewProvider interface {
	mock.TestingT
	Cleanup(func())
}

// NewProvider creates a new instance of Provider. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
func NewProvider(t mockConstructorTestingTNewProvider) *Provider {
	mock := &Provider{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
