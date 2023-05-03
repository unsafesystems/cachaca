package logger

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type ginHands struct {
	Path       string
	Latency    time.Duration
	Method     string
	StatusCode int
	ClientIP   string
	MsgStr     string
}

func ErrorLogger() gin.HandlerFunc {
	return ErrorLoggerT(gin.ErrorTypeAny)
}

func ErrorLoggerT(typ gin.ErrorType) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		ctx.Next()

		if !ctx.Writer.Written() {
			json := ctx.Errors.ByType(typ).JSON()
			if json != nil {
				ctx.JSON(-1, json)
			}
		}
	}
}

func Logger() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		timestamp := time.Now()
		// before request
		path := ctx.Request.URL.Path
		raw := ctx.Request.URL.RawQuery
		ctx.Next()
		// after request
		// latency := time.Since(t)
		// clientIP := c.ClientIP()
		// method := c.Request.Method
		// statusCode := c.Writer.Status()
		if raw != "" {
			path = path + "?" + raw
		}

		msg := ctx.Errors.String()
		if msg == "" {
			msg = "Request"
		}

		cData := &ginHands{
			Path:       path,
			Latency:    time.Since(timestamp),
			Method:     ctx.Request.Method,
			StatusCode: ctx.Writer.Status(),
			ClientIP:   ctx.ClientIP(),
			MsgStr:     msg,
		}

		logSwitch(cData)
	}
}

func logSwitch(data *ginHands) {
	var event *zerolog.Event

	switch {
	case data.StatusCode >= http.StatusBadRequest && data.StatusCode < http.StatusInternalServerError:
		event = log.Warn()
	case data.StatusCode >= http.StatusInternalServerError:
		event = log.Error()
	default:
		event = log.Info()
	}

	event.Str("method", data.Method).
		Str("path", data.Path).
		Dur("resp_time", data.Latency).
		Int("status", data.StatusCode).
		Str("client_ip", data.ClientIP).
		Msg(data.MsgStr)
}
