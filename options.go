//nolint:ireturn
package cachaca

import (
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Option interface {
	Apply(*Server) error
}

type grpcWebDisabled struct{}

func (*grpcWebDisabled) Apply(s *Server) error {
	s.GrpcWebDisabled = true

	return nil
}

// GRPCWebDisabled disables the grpc-web endpoint.
func GRPCWebDisabled() Option {
	return &grpcWebDisabled{}
}

type insecureHealth struct{}

func (*insecureHealth) Apply(s *Server) error {
	s.InsecureHealth = true

	return nil
}

// InsecureHealth disables authentication on the health endpoint. Otherwise, the health endpoint will be protected
// by the authentication middleware and requires at least a valid token or certificate.
func InsecureHealth() Option {
	return &insecureHealth{}
}

type readTimeout struct {
	timeout time.Duration
}

func (opt *readTimeout) Apply(s *Server) error {
	s.ReadTimeout = opt.timeout

	return nil
}

// WithReadTimeout sets the read timeout for the http server.
func WithReadTimeout(timeout time.Duration) Option {
	return &readTimeout{timeout: timeout}
}

type embeddedMetricsEndpoint struct{}

func (*embeddedMetricsEndpoint) Apply(s *Server) error {
	s.GET("/metrics", gin.WrapH(promhttp.Handler()))

	return nil
}

// WithEmbeddedMetricsEndpoint enables the prometheus metrics on the /metrics endpoint. Please note that when using
// a custom http handler this option will not be applied successfully.
func WithEmbeddedMetricsEndpoint() Option {
	return &embeddedMetricsEndpoint{}
}

type ginMiddleware struct {
	middleware gin.HandlerFunc
}

func (opt *ginMiddleware) Apply(s *Server) error {
	s.Use(opt.middleware)

	return nil
}

func WithGinMiddleware(middleware gin.HandlerFunc) Option {
	return &ginMiddleware{middleware: middleware}
}
