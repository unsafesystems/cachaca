//nolint
package cachaca

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"reflect"
	"runtime"
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

func TestServer_Middleware(t *testing.T) {
	handler := func(ctx *gin.Context) {}
	s, err := NewServer(WithGinMiddleware(handler))
	assert.Nil(t, err)
	assert.Equal(t, 4, len(s.Engine.Handlers))

	// First two middlewares are panic and logging middleware, last one is the authorizer
	assert.Equal(t,
		runtime.FuncForPC(reflect.ValueOf(handler).Pointer()).Name(),
		runtime.FuncForPC(reflect.ValueOf(s.Engine.Handlers[2]).Pointer()).Name(),
	)
}

func TestServer_Reflection(t *testing.T) {
	s, err := NewServer(WithServerReflection())
	assert.NoError(t, err)
	assert.True(t, s.ServerReflection)
}
