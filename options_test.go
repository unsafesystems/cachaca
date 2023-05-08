//nolint
package cachaca

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestServer_DisableGrpcWeb(t *testing.T) {
	s, err := NewServer(GRPCWebDisabled())
	assert.Nil(t, err)
	assert.Nil(t, s.GrpcWeb)
}

type FaultyOption struct{}

func (opt *FaultyOption) Apply(*Server) error {
	return fmt.Errorf("error")
}

func TestServer_FaultyOption(t *testing.T) {
	_, err := NewServer(&FaultyOption{})
	assert.NotNil(t, err)
}

func TestServer_ReadTimeout(t *testing.T) {
	s, err := NewServer(WithReadTimeout(time.Second))
	assert.Nil(t, err)
	assert.Equal(t, time.Second, s.ReadTimeout)
}
