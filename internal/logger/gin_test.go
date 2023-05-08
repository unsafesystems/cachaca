//nolint
package logger

import (
	"bytes"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestGin_Logger(t *testing.T) {
	middleware := NewGinLogger()
	assert.NotNil(t, middleware, "Can't get NewGinLogger middleware")
}

func TestGin_LogSwitch(t *testing.T) {
	buf := &bytes.Buffer{}
	log := zerolog.New(buf)

	testCdata := &ginHands{
		logger:     &log,
		path:       "/post",
		latency:    1 * time.Second,
		method:     "GET",
		statusCode: 200,
		clientIP:   "127.0.0.1",
		msgStr:     "",
	}
	logSwitch(testCdata)
	assert.NotNil(t, "", "Can't get logSwitch middleware")
}

func TestGin_Server(t *testing.T) {
	buf := &bytes.Buffer{}
	log := zerolog.New(buf)

	gin.SetMode(gin.ReleaseMode)
	g := gin.New()
	g.Use(NewGinLogger(&log))

	g.GET("/404", func(c *gin.Context) {
		c.String(http.StatusNotFound, "404 Not Found")
	})
	g.GET("/500", func(c *gin.Context) {
		c.String(http.StatusInternalServerError, "500 Internal Server Error")
	})
	g.GET("/ping", func(c *gin.Context) {
		c.String(http.StatusOK, "pong")
	})

	l, err := net.Listen("tcp", fmt.Sprintf(":%d", 0))
	require.Nil(t, err)
	port := l.Addr().(*net.TCPAddr).Port

	go g.RunListener(l)

	resp, err := http.Get(fmt.Sprintf("http://localhost:%d/ping", port))
	require.Nil(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Regexp(t, `^{"level":"info","method":"GET","path":"/ping","raw":"","resp_time":.*,"status":200,"client_ip":"::1","message":"Request"}`, buf.String())
	buf.Reset()

	resp, err = http.Get(fmt.Sprintf("http://localhost:%d/404", port))
	require.Nil(t, err)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	assert.Regexp(t, `^{"level":"warn","method":"GET","path":"/404","raw":"","resp_time":.*,"status":404,"client_ip":"::1","message":"Request"}`, buf.String())
	buf.Reset()

	resp, err = http.Get(fmt.Sprintf("http://localhost:%d/500", port))
	require.Nil(t, err)
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	assert.Regexp(t, `^{"level":"error","method":"GET","path":"/500","raw":"","resp_time":.*,"status":500,"client_ip":"::1","message":"Request"}`, buf.String())
	buf.Reset()

	resp, err = http.Get(fmt.Sprintf("http://localhost:%d/ping?test", port))
	require.Nil(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Regexp(t, `^{"level":"info","method":"GET","path":"/ping","raw":"test","resp_time":.*,"status":200,"client_ip":"::1","message":"Request"}`, buf.String())
	buf.Reset()
}
