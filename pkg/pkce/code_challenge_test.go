package pkce

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func TestChallenge(t *testing.T) {
	code := Code("s256test")
	cfg := oauth2.Config{}
	authCodeURL, err := url.Parse(cfg.AuthCodeURL("", code.Challenge()...))
	require.NoError(t, err)

	assert.Equal(t, "W6YWc_4yHwYN-cGDgGmOMHF3l7KDy7VcRjf7q2FVF-o", authCodeURL.Query().Get("code_challenge"))
	assert.Equal(t, "S256", authCodeURL.Query().Get("code_challenge_method"))
}

func TestVerifier(t *testing.T) {
	code := Code("s256test")
	cfg := oauth2.Config{}
	authCodeURL, err := url.Parse(cfg.AuthCodeURL("", code.Verifier()...))
	require.NoError(t, err)

	assert.Equal(t, "s256test", authCodeURL.Query().Get("code_verifier"))
}

func TestGenerate(t *testing.T) {
	code, err := Generate(64)
	require.NoError(t, err)
	assert.Equal(t, 64, len(*code))

	code, err = Generate(0)
	require.NoError(t, err)
	assert.Equal(t, 43, len(*code))

	code, err = Generate(128)
	require.NoError(t, err)
	assert.Equal(t, 128, len(*code))

	code, err = Generate(129)
	require.NoError(t, err)
	assert.Equal(t, 128, len(*code))

	code, err = Generate(43)
	require.NoError(t, err)
	assert.Equal(t, 43, len(*code))
}
