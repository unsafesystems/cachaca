//nolint
package oidc

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/google/uuid"
	"github.com/oauth2-proxy/mockoidc"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/unsafesystems/cachaca"
	"github.com/zitadel/oidc/v2/pkg/client/rp"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"testing"
)

func TestOIDC(t *testing.T) {
	suite.Run(t, new(OIDCTestSuite))
}

type OIDCTestSuite struct {
	suite.Suite
	mock       *mockoidc.MockOIDC
	server     *cachaca.Server
	listener   net.Listener
	port       int
	signingKey *jose.SigningKey
}

func (s *OIDCTestSuite) SetupSuite() {
	zerolog.SetGlobalLevel(zerolog.Disabled)

	m, err := mockoidc.Run()
	require.Nil(s.T(), err)

	s.mock = m

	cfg := m.Config()

	l, err := net.Listen("tcp", fmt.Sprintf(":%d", 0))
	require.Nil(s.T(), err)
	s.port = l.Addr().(*net.TCPAddr).Port

	redirectUri := fmt.Sprintf("http://localhost:%d/oidc/authorize", s.port)

	provider, err := rp.NewRelyingPartyOIDC(cfg.Issuer, cfg.ClientID, m.ClientSecret, redirectUri, []string{"openid", "profile", "email"})
	require.Nil(s.T(), err)

	s.signingKey = &jose.SigningKey{Algorithm: jose.HS256, Key: []byte(uuid.NewString())}

	authorizer := NewAuthorizer(s.signingKey)
	authorizer.RegisterRelyingParty("test", provider)

	server, err := cachaca.NewServer(
		cachaca.WithGinMiddleware(func(c *gin.Context) {
			c.Next()

			if len(c.Errors) > 0 {
				c.JSON(-1, gin.H{"error": c.Errors[0].Error()})
			}
		}),
		authorizer,
	)
	require.Nil(s.T(), err)

	go func() {
		err := server.Serve(l)
		if err != nil {
			panic(err)
		}
	}()

	s.server = server
	s.listener = l

}

func (s *OIDCTestSuite) TearDownSuite() {
	err := s.mock.Shutdown()
	require.Nil(s.T(), err)
}

func (s *OIDCTestSuite) TestDummy() {
	s.T().Log("TODO")
}

func (s *OIDCTestSuite) TestHappyPath() {
	// This ensures that the client doesn't follow any redirects
	jar, err := cookiejar.New(nil)
	require.Nil(s.T(), err)
	client := &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	endpoints := []string{
		"login",
		"login/",
		"login/test",
		"login/test/",
	}

	for _, ep := range endpoints {
		// First we initialize the flow with a login request
		res, err := client.Get(fmt.Sprintf("http://localhost:%d/oidc/%s", s.port, ep))
		require.Nil(s.T(), err)
		require.Equal(s.T(), http.StatusFound, res.StatusCode)

		loc := res.Header.Get("Location")
		uri, err := url.Parse(loc)
		require.Nil(s.T(), err)

		query := uri.Query()
		require.Equal(s.T(), s.mock.AuthorizationEndpoint(), uri.Scheme+"://"+uri.Host+uri.Path)
		require.True(s.T(), query.Has("client_id"))
		require.True(s.T(), query.Has("redirect_uri"))
		require.True(s.T(), query.Has("response_type"))
		require.True(s.T(), query.Has("scope"))
		require.True(s.T(), query.Has("state"))

		require.Equal(s.T(), s.mock.Config().ClientID, query.Get("client_id"))
		require.Equal(s.T(), "code", query.Get("response_type"))
		require.Equal(s.T(), "openid profile email", query.Get("scope"))

		// We check that a valid state cookie has been set
		cookies := res.Cookies()
		require.Len(s.T(), cookies, 1)

		cookie := cookies[0]
		require.Equal(s.T(), "cachaca-state", cookie.Name)
		require.Equal(s.T(), "/", cookie.Path)

		claims := new(jwt.Claims)
		err = parseJWT(cookie.Value, s.signingKey, claims)
		require.Nil(s.T(), err)
		require.Equal(s.T(), query.Get("state"), claims.Subject)

		// We can now use the generated url from the redirect to call to the OIDC provider. We expect that the state is
		// kept and that we receive a code in the response.
		user := &mockoidc.MockUser{
			Subject:           "user1",
			Email:             "user1@example.org",
			EmailVerified:     true,
			PreferredUsername: "",
			Phone:             "",
			Address:           "",
			Groups:            nil,
		}
		s.mock.QueueUser(user)

		code := uuid.NewString()
		s.mock.QueueCode(code)

		res, err = client.Get(loc)
		require.Nil(s.T(), err)
		assert.Equal(s.T(), http.StatusFound, res.StatusCode)
		loc = res.Header.Get("Location")

		uri, err = url.Parse(loc)
		require.Nil(s.T(), err)
		assert.Equal(s.T(), fmt.Sprintf("http://localhost:%d/oidc/authorize", s.port), uri.Scheme+"://"+uri.Host+uri.Path)

		query = uri.Query()
		require.Equal(s.T(), code, query.Get("code"))
		require.Equal(s.T(), query.Get("state"), claims.Subject)

		// Last but not least we "redirect" back to our service. This should complete the login.
		res, err = client.Get(loc)
		require.NoError(s.T(), err)
		assert.Equal(s.T(), http.StatusFound, res.StatusCode)

		loc = res.Header.Get("Location")
		uri, err = url.Parse(loc)
		require.Nil(s.T(), err)
		assert.Equal(s.T(), fmt.Sprintf("http://localhost:%d/oidc/success", s.port), loc)

		// Validate the session cookie
		cookies = res.Cookies()
		require.Len(s.T(), cookies, 1)

		cookie = cookies[0]
		require.Equal(s.T(), "cachaca-session", cookie.Name)

		tok, err := jwt.ParseSigned(cookie.Value)
		require.Nil(s.T(), err)
		require.Equal(s.T(), 1, len(tok.Headers))
		assert.Equal(s.T(), "HS256", tok.Headers[0].Algorithm)

		cl := jwt.Claims{}
		err = tok.Claims(s.signingKey.Key, &cl)
		require.Nil(s.T(), err)

		require.Equal(s.T(), user.Subject, cl.Subject)
	}
}

func (s *OIDCTestSuite) TestUnknownProvider() {
	res, err := http.Get(fmt.Sprintf("http://localhost:%d/oidc/login/unknown", s.port))
	require.Nil(s.T(), err)
	assert.Equal(s.T(), http.StatusNotFound, res.StatusCode)

	res, err = http.Get(fmt.Sprintf("http://localhost:%d/oidc/authorize/unknown", s.port))
	require.Nil(s.T(), err)
	assert.Equal(s.T(), http.StatusNotFound, res.StatusCode)
}

func (s *OIDCTestSuite) TestErrorHandler() {
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	res, err := client.Get(fmt.Sprintf("http://localhost:%d/oidc/authorize?error=test&error_description=description", s.port))
	require.Nil(s.T(), err)
	assert.Equal(s.T(), http.StatusFound, res.StatusCode)
	loc := res.Header.Get("Location")
	assert.Equal(s.T(), "/oidc/error?error=test&error_description=description", loc)
}

func (s *OIDCTestSuite) TestMissingStateCookie() {
	// Because we don't use a cookie jar the cookie will be missing
	res, err := http.Get(fmt.Sprintf("http://localhost:%d/oidc/login", s.port))
	require.Nil(s.T(), err)

	assert.Equal(s.T(), http.StatusUnauthorized, res.StatusCode)
	body, err := io.ReadAll(res.Body)
	require.Nil(s.T(), err)
	assert.Contains(s.T(), string(body), "state cookie missing")
}
