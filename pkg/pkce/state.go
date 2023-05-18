package pkce

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
)

const (
	MaxStateAge    = 10 * time.Minute // 10 minutes is recommended by the spec
	MinStateLength = 43
	MaxStateLength = 128
)

var ErrStateVerificationFailed = errors.New("state verification failed")

type State struct {
	state string
	code  *Code
}

func Validate(value string, state string, iss string, sigKey interface{}, decKey interface{}) (*Code, error) {
	nestedToken, err := jwt.ParseSignedAndEncrypted(value)
	if err != nil {
		return nil, ErrStateVerificationFailed
	}

	token, err := nestedToken.Decrypt(decKey)
	if err != nil {
		return nil, ErrStateVerificationFailed
	}

	var claims jwt.Claims

	err = token.Claims(sigKey, &claims)
	if err != nil {
		return nil, ErrStateVerificationFailed
	}

	err = claims.Validate(jwt.Expected{
		Issuer:   iss,
		Audience: jwt.Audience{iss},
		ID:       state,
		Time:     time.Now(),
	})
	if err != nil {
		return nil, ErrStateVerificationFailed
	}

	code := Code(claims.Subject)

	return &code, nil
}

func NewState(length int, code *Code) (*State, error) {
	length = limitRange(length, MinStateLength, MaxStateLength)

	//nolint:gomnd
	key := make([]byte, (length*6)/8)

	_, err := rand.Read(key)
	if err != nil {
		return nil, fmt.Errorf("failed to generate state: %w", err)
	}

	state := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(key)

	return &State{
		state: state,
		code:  code,
	}, nil
}

func (s *State) Marshal(iss string, sig jose.Signer, enc jose.Encrypter) (string, error) {
	subject := ""
	if s.code != nil {
		subject = string(*s.code)
	}

	expiry := time.Now().Add(MaxStateAge)
	claims := &jwt.Claims{
		ID:        s.state,
		Issuer:    iss,
		Subject:   subject,
		Audience:  jwt.Audience{iss},
		Expiry:    jwt.NewNumericDate(expiry),
		NotBefore: jwt.NewNumericDate(time.Now()),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
	}

	token, err := jwt.SignedAndEncrypted(sig, enc).Claims(claims).CompactSerialize()
	if err != nil {
		return "", fmt.Errorf("failed to marshal state: %w", err)
	}

	return token, nil
}

func (s *State) State() string {
	return s.state
}
