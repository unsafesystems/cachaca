package logger

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"
	zlog "github.com/rs/zerolog/log"
)

type ginHands struct {
	logger     *zerolog.Logger
	path       string
	latency    time.Duration
	method     string
	statusCode int
	clientIP   string
	msgStr     string
	raw        string
}

func NewGinLogger(logger ...*zerolog.Logger) gin.HandlerFunc {
	var log *zerolog.Logger
	if len(logger) > 0 {
		log = logger[0]
	}

	return func(ctx *gin.Context) {
		timestamp := time.Now()
		// before request
		path := ctx.Request.URL.Path
		raw := ctx.Request.URL.RawQuery
		ctx.Next()

		msg := ctx.Errors.String()
		if msg == "" {
			msg = "Request"
		}

		cData := &ginHands{
			logger:     log,
			path:       path,
			latency:    time.Since(timestamp),
			method:     ctx.Request.Method,
			statusCode: ctx.Writer.Status(),
			clientIP:   ctx.ClientIP(),
			msgStr:     msg,
			raw:        raw,
		}

		logSwitch(cData)
	}
}

func logSwitch(data *ginHands) {
	log := data.logger
	if log == nil {
		log = &zlog.Logger
	}

	var event *zerolog.Event

	switch {
	case data.statusCode >= http.StatusBadRequest && data.statusCode < http.StatusInternalServerError:
		event = log.Warn()
	case data.statusCode >= http.StatusInternalServerError:
		event = log.Error()
	default:
		event = log.Info()
	}

	event.Str("method", data.method).
		Str("path", data.path).
		Str("raw", data.raw).
		Dur("resp_time", data.latency).
		Int("status", data.statusCode).
		Str("client_ip", data.clientIP).
		Msg(data.msgStr)
}
