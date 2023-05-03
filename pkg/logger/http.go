package logger

import (
	"log"
	"strings"

	zero "github.com/rs/zerolog/log"
)

func NewHTTPErrorLogger() *log.Logger {
	return log.New(&HTTPErrorLogger{}, "", 0)
}

type HTTPErrorLogger struct{}

func (h HTTPErrorLogger) Write(p []byte) (int, error) {
	msg := string(p)
	zero.Error().Str("service", "http").Msg(strings.Trim(msg, "\r\n "))

	return len(p), nil
}
