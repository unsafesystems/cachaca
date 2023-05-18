package pkce

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"golang.org/x/oauth2"
)

const (
	MinPKCELength = 43
	MaxPKCELength = 128
)

// Code implements the basic options required for RFC 7636: Proof Key for Code Exchange (PKCE).
type Code string

// Generate returns a new PKCE code verifier with the given length (in characters).
func Generate(length int) (*Code, error) {
	// From https://tools.ietf.org/html/rfc7636#section-4.1:
	//   code_verifier = high-entropy cryptographic random STRING using the
	//   unreserved characters [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"
	//   from Section 2.3 of [RFC3986], with a minimum length of 43 characters
	//   and a maximum length of 128 characters.
	length = limitRange(length, MinPKCELength, MaxPKCELength)

	//nolint:gomnd
	key := make([]byte, (length*6)/8)

	_, err := rand.Read(key)
	if err != nil {
		return nil, fmt.Errorf("failed to generate state: %w", err)
	}

	verifier := Code(base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(key))

	return &verifier, nil
}

// Challenge returns the OAuth2 auth code parameter for sending the PKCE code challenge.
func (c *Code) Challenge() []oauth2.AuthCodeOption {
	s256 := sha256.Sum256([]byte(*c))
	challenge := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(s256[:])

	return []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	}
}

// Verifier returns the OAuth2 auth code parameter for sending the PKCE code verifier.
func (c *Code) Verifier() []oauth2.AuthCodeOption {
	return []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("code_verifier", string(*c)),
	}
}

type Signed interface {
	~int | ~int8 | ~int16 | ~int32 | ~int64
}

type Unsigned interface {
	~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64 | ~uintptr
}
type Float interface {
	~float32 | ~float64
}

type Integer interface {
	Signed | Unsigned
}

type Ordered interface {
	Integer | Float | ~string
}

func limitRange[T Ordered](val T, min T, max T) T {
	if val < min {
		return min
	}

	if val > max {
		return max
	}

	return val
}
