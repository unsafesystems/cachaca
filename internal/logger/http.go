package logger

import (
	"log"
	"strings"

	"github.com/rs/zerolog"
	zlog "github.com/rs/zerolog/log"
)

func NewHTTPErrorLogger(logger ...*zerolog.Logger) *log.Logger {
	httpLogger := &HTTPErrorLogger{
		logger: &zlog.Logger,
	}

	if len(logger) > 0 {
		httpLogger.logger = logger[0]
	}

	return log.New(httpLogger, "", 0)
}

type HTTPErrorLogger struct {
	logger *zerolog.Logger
}

func (h *HTTPErrorLogger) Write(p []byte) (int, error) {
	msg := strings.Trim(string(p), "\r\n ")
	h.logger.Error().Str("service", "http").Msg(msg)

	return len(p), nil
}
