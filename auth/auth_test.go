//nolint
package auth

import (
	"context"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestAuth(t *testing.T) {
	ctx := context.Background()

	_, ok := GetCreds(ctx)
	assert.False(t, ok)

	auth := Authentication{}
	ctx = WithCreds(ctx, auth)

	creds, ok := GetCreds(ctx)
	assert.True(t, ok)
	assert.Equal(t, auth, *creds)
}
