//nolint
package logger

import (
	"bytes"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestHttp_NewLine(t *testing.T) {
	buf := &bytes.Buffer{}
	l := zerolog.New(buf)
	logger := NewHTTPErrorLogger(&l)

	logger.Println("test")
	assert.Equal(t, "{\"level\":\"error\",\"service\":\"http\",\"message\":\"test\"}\n", buf.String())
	buf.Reset()

	logger.Printf("test %s", "test")
	assert.Equal(t, "{\"level\":\"error\",\"service\":\"http\",\"message\":\"test test\"}\n", buf.String())
	buf.Reset()

	logger.Print("test \r\n")
	assert.Equal(t, "{\"level\":\"error\",\"service\":\"http\",\"message\":\"test\"}\n", buf.String())
	buf.Reset()
}
