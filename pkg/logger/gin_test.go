package logger

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func Test_ErrorLogger(t *testing.T) {
	t.Parallel()

	middleware := ErrorLogger()
	assert.NotNil(t, middleware, "Can't get ErrorLogger middleware")
}

func Test_Logger(t *testing.T) {
	t.Parallel()

	middleware := Logger()
	assert.NotNil(t, middleware, "Can't get Logger middleware")
}

func Test_logSwitch(t *testing.T) {
	t.Parallel()

	testCdata := &ginHands{
		Path:       "/post",
		Latency:    1 * time.Second,
		Method:     "GET",
		StatusCode: 200,
		ClientIP:   "127.0.0.1",
		MsgStr:     "",
	}
	logSwitch(testCdata)
	assert.NotNil(t, "", "Can't get logSwitch middleware")
}
