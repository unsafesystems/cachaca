//nolint
package oidc

import (
	"encoding/base64"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestSnakeCase(t *testing.T) {
	assert.Equal(t, "snake_case", toSnakeCase("SnakeCase"))
	assert.Equal(t, "snake_case", toSnakeCase("Snake Case"))
}

func TestSecureKey(t *testing.T) {
	key, err := generateSecureKey(1)
	assert.NoError(t, err)
	buf, err := base64.RawURLEncoding.DecodeString(key)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(buf))

	key, err = generateSecureKey(9)
	assert.NoError(t, err)
	buf, err = base64.RawURLEncoding.DecodeString(key)
	assert.NoError(t, err)
	assert.Equal(t, 2, len(buf))
}
