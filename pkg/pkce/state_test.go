//nolint
package pkce

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/go-jose/go-jose/v3"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

func TestState(t *testing.T) {
	suite.Run(t, new(StateTestSuite))
}

type StateTestSuite struct {
	suite.Suite
	privateKey *rsa.PrivateKey
	encrypter  jose.Encrypter
	signingKey []byte
	signer     jose.Signer
}

func (s *StateTestSuite) SetupSuite() {
	var err error

	s.privateKey, err = rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(s.T(), err)

	s.encrypter, err = jose.NewEncrypter(jose.A128GCM, jose.Recipient{
		Algorithm: jose.RSA_OAEP,
		Key:       s.privateKey.Public(),
	}, (&jose.EncrypterOptions{}).WithType("JWT").WithContentType("JWT"))
	require.NoError(s.T(), err)

	s.signingKey = make([]byte, 32)
	_, err = rand.Read(s.signingKey)
	require.NoError(s.T(), err)

	s.signer, err = jose.NewSigner(jose.SigningKey{
		Algorithm: jose.HS256,
		Key:       s.signingKey,
	}, nil)
	require.NoError(s.T(), err)
}

func (s *StateTestSuite) TestHappyPath() {
	issuer := "http://localhost"

	code, err := Generate(43)
	require.NoError(s.T(), err)

	state, err := NewState(43, code)
	require.NoError(s.T(), err)

	token, err := state.Marshal(issuer, s.signer, s.encrypter)
	require.NoError(s.T(), err)

	c, err := Validate(token, state.State(), issuer, s.signingKey, s.privateKey)
	require.NoError(s.T(), err)

	require.Equal(s.T(), string(*code), string(*c))
}

func (s *StateTestSuite) TestInvalidState() {
	issuer := "http://localhost"

	state, err := NewState(0, nil)
	require.NoError(s.T(), err)
	require.Equal(s.T(), 43, len(state.state))

	token, err := state.Marshal(issuer, s.signer, s.encrypter)
	require.NoError(s.T(), err)

	_, err = Validate(token, "invalid", issuer, s.signingKey, s.privateKey)
	require.Error(s.T(), err)
}

func (s *StateTestSuite) TestValidationErrors() {
	issuer := "http://localhost"

	state, err := NewState(0, nil)
	require.NoError(s.T(), err)
	require.Equal(s.T(), 43, len(state.state))

	token, err := state.Marshal(issuer, s.signer, s.encrypter)
	require.NoError(s.T(), err)

	// Invalid issuer
	_, err = Validate(token, state.State(), "invalid", s.signingKey, s.privateKey)
	require.Error(s.T(), err)

	// corrupt token
	_, err = Validate("hello world", state.state, "invalid", s.signingKey, s.privateKey)
	require.Error(s.T(), err)

	// invalid encryption key
	_, err = Validate(token, state.State(), issuer, s.signingKey, &rsa.PrivateKey{})
	require.Error(s.T(), err)

	// invalid signing key
	_, err = Validate(token, state.State(), issuer, s.signingKey[:16], s.privateKey)
	require.Error(s.T(), err)
}
