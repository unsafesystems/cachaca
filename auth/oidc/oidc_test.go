//nolint
package oidc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/google/uuid"
	"github.com/oauth2-proxy/mockoidc"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/unsafesystems/cachaca"
	"github.com/zitadel/oidc/v2/pkg/client/rp"
	"github.com/zitadel/oidc/v2/pkg/oidc"
	"golang.org/x/oauth2"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestOIDC(t *testing.T) {
	suite.Run(t, new(OIDCTestSuite))
}

type OIDCTestSuite struct {
	suite.Suite
	mock       *mockoidc.MockOIDC
	server     *cachaca.Server
	authorizer *Authorizer
	provider   rp.RelyingParty
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

	s.provider, err = rp.NewRelyingPartyOIDC(cfg.Issuer, cfg.ClientID, m.ClientSecret, redirectUri, []string{"openid", "profile", "email"})
	require.Nil(s.T(), err)

	s.signingKey = &jose.SigningKey{Algorithm: jose.HS256, Key: []byte(uuid.NewString())}

	s.authorizer = NewAuthorizer(s.signingKey)
	s.authorizer.RegisterRelyingParty("test", s.provider)

	server, err := cachaca.NewServer(
		cachaca.WithGinMiddleware(func(c *gin.Context) {
			c.Next()

			if len(c.Errors) > 0 {
				c.JSON(-1, gin.H{"error": c.Errors[0].Error()})
			}
		}),
		s.authorizer,
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

	s.server.GET("/ping", func(c *gin.Context) {
		c.String(http.StatusOK, "pong")
	})
}

func (s *OIDCTestSuite) TearDownSuite() {
	err := s.mock.Shutdown()
	require.Nil(s.T(), err)
}

func (s *OIDCTestSuite) TestRPAlreadyRegistered() {
	assert.Panics(s.T(), func() {
		s.authorizer.RegisterRelyingParty("test", nil)
	})

	assert.Panics(s.T(), func() {
		s.authorizer.RegisterRelyingParty("test", s.provider)
	})
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
		assert.Equal(s.T(), "/oidc/success", loc)

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

func (s *OIDCTestSuite) generateToken(id string, expiry time.Time) string {
	signer, err := jose.NewSigner(*s.signingKey, nil)
	require.Nil(s.T(), err)

	session := &Session{
		ID: id,
		Tokens: &oidc.Tokens[*oidc.IDTokenClaims]{
			Token: &oauth2.Token{
				AccessToken:  "access_token",
				RefreshToken: "refresh_token",
				Expiry:       expiry,
			},
		},
		UserInfo: nil,
		Issuer:   s.provider.Issuer(),
		provider: s.provider,
		dirty:    false,
	}

	token, err := session.generateJWT(context.Background(), signer, nil)
	require.Nil(s.T(), err)

	return token
}

func (s *OIDCTestSuite) TestPingUnauthenticated() {
	res, err := http.Get(fmt.Sprintf("http://localhost:%d/ping", s.port))
	require.Nil(s.T(), err)
	assert.Equal(s.T(), http.StatusUnauthorized, res.StatusCode)
}

func (s *OIDCTestSuite) TestPingAuthenticated() {
	token := s.generateToken(uuid.NewString(), time.Now().Add(time.Hour))

	req, err := http.NewRequest("GET", fmt.Sprintf("http://localhost:%d/ping", s.port), nil)
	require.Nil(s.T(), err)
	req.Header.Add("Authorization", "Bearer "+token)

	client := &http.Client{}
	res, err := client.Do(req)
	require.Nil(s.T(), err)
	assert.Equal(s.T(), http.StatusOK, res.StatusCode)

	body, err := io.ReadAll(res.Body)
	require.Nil(s.T(), err)
	assert.Equal(s.T(), "pong", string(body))
}

func (s *OIDCTestSuite) TestLogout() {
	res, err := http.Get(fmt.Sprintf("http://localhost:%d/oidc/logout", s.port))
	require.Nil(s.T(), err)
	assert.Equal(s.T(), http.StatusUnauthorized, res.StatusCode)

	id := uuid.NewString()
	token := s.generateToken(id, time.Now().Add(time.Hour))

	storage := NewMockStorage(s.T())
	s.authorizer.storage = storage
	storage.On("Delete", mock.Anything, id).Return(nil).Once()

	req, err := http.NewRequest("GET", fmt.Sprintf("http://localhost:%d/oidc/logout", s.port), nil)
	require.Nil(s.T(), err)
	req.Header.Add("Authorization", "Bearer "+token)

	client := &http.Client{}
	res, err = client.Do(req)
	require.Nil(s.T(), err)
	assert.Equal(s.T(), http.StatusNoContent, res.StatusCode)

	require.Equal(s.T(), 1, len(res.Cookies()))
	assert.Equal(s.T(), "cachaca-session", res.Cookies()[0].Name)
	assert.Equal(s.T(), -1, res.Cookies()[0].MaxAge)
	assert.Equal(s.T(), "Bearer invalid", res.Header.Get("Authorization"))

	s.authorizer.storage = nil
}

func (s *OIDCTestSuite) TestTransparentAuthentication() {
	// This test will attempt to access the /ping endpoint without any previous authorization.
	// Because Golang handles all the redirects internally and the OIDC server will happily log us in we should end
	// up receiving the expected pong response from the /ping endpoint.

	user := &mockoidc.MockUser{
		Subject:           "user2",
		Email:             "user2@example.org",
		EmailVerified:     true,
		PreferredUsername: "",
		Phone:             "",
		Address:           "",
		Groups:            nil,
	}
	s.mock.QueueUser(user)

	jar, err := cookiejar.New(nil)
	require.Nil(s.T(), err)
	client := &http.Client{
		Jar: jar,
	}

	successURL := s.authorizer.successURL
	s.authorizer.successURL = "/ping"
	s.authorizer.storage = NewMemoryStorage()

	res, err := client.Get(fmt.Sprintf("http://localhost:%d/oidc/login", s.port))
	require.Nil(s.T(), err)
	assert.Equal(s.T(), http.StatusOK, res.StatusCode)

	body, err := io.ReadAll(res.Body)
	require.Nil(s.T(), err)
	assert.Equal(s.T(), "pong", string(body))

	// Now that we are logged in - we can see what happens when we try to access the /ping endpoint with an expired
	// token. This should still work because the server is supposed to handle the re-authentication with the OIDC
	// server transparently.
	var token string
	cookie := jar.Cookies(res.Request.URL)
	for _, c := range cookie {
		if c.Name == "cachaca-session" {
			// Here we replace the expiry of the JWT token in the session cookie with a new one.
			// This effectively invalidates the session cookie and the server is forced to re-authenticate.
			type idStruct struct {
				ID string `json:"jti"`
			}
			id := new(idStruct)

			raw, err := base64.RawURLEncoding.DecodeString(strings.Split(c.Value, ".")[1])
			require.Nil(s.T(), err)

			err = json.Unmarshal(raw, id)
			require.Nil(s.T(), err)

			c.Value = s.generateToken(id.ID, time.Now().Add(-1*time.Hour))
			token = c.Value
			jar.SetCookies(res.Request.URL, []*http.Cookie{c})
			break
		}
	}

	s.mock.QueueUser(user)

	res, err = client.Get(fmt.Sprintf("http://localhost:%d/ping", s.port))
	require.Nil(s.T(), err)
	assert.Equal(s.T(), http.StatusOK, res.StatusCode)

	body, err = io.ReadAll(res.Body)
	require.Nil(s.T(), err)
	assert.Equal(s.T(), "pong", string(body))

	assert.NotEqual(s.T(), "", res.Header.Get("Authorization"))
	assert.NotEqual(s.T(), "Bearer "+token, res.Header.Get("Authorization"))
	assert.NotEqual(s.T(), jar.Cookies(res.Request.URL)[0].Value, token)

	s.authorizer.successURL = successURL
	s.authorizer.storage = nil
}

func TestMissingSigningKey(t *testing.T) {
	assert.Panics(t, func() {
		NewAuthorizer(nil)
	})

	assert.Panics(t, func() {
		NewAuthorizer(&jose.SigningKey{
			Algorithm: "",
			Key:       nil,
		})
	})

	assert.Panics(t, func() {
		NewAuthorizer(&jose.SigningKey{
			Algorithm: "HS256",
			Key:       nil,
		})
	})

	assert.Panics(t, func() {
		NewAuthorizer(&jose.SigningKey{
			Algorithm: "",
			Key:       []byte("test"),
		})
	})
}
