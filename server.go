package cachaca

import (
	"cachaca/internal/logger"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/recovery"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/selector"
	"github.com/improbable-eng/grpc-web/go/grpcweb"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog/log"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/health"
	healthgrpc "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
)

const (
	grpcContentType    = "application/grpc"
	grpcWebContentType = "application/grpc-web"
	defaultReadTimeout = 10 * time.Second
)

// Server is an opinionated implementation of server providing grpc, grpc-web and rest/http endpoints on a single port.
type Server struct {
	*gin.Engine
	tls             *tls.Config
	grpcWebDisabled bool
	grpcweb         *grpcweb.WrappedGrpcServer
	grpc            *grpc.Server
	http            http.Handler
	server          *http.Server
	healthcheck     *health.Server

	readTimeout    time.Duration
	jwtKeyFunc     jwt.Keyfunc
	jwtToken       jwt.Claims
	insecureHealth bool
}

type Option func(*Server) error

// DisableGrpcWeb disables the grpc-web endpoint.
func DisableGrpcWeb() Option {
	return func(s *Server) error {
		s.grpcWebDisabled = true

		return nil
	}
}

// WithInsecureHealth disables authentication on the health endpoint. Otherwise, the health endpoint will be protected
// by the authentication middleware and requires at least a valid token or certificate.
func WithInsecureHealth() Option {
	return func(s *Server) error {
		s.insecureHealth = true

		return nil
	}
}

// WithJwtKeyFunc sets the jwt key function for the authentication middleware.
func WithJwtKeyFunc(keyFunc jwt.Keyfunc) Option {
	return func(s *Server) error {
		s.jwtKeyFunc = keyFunc

		return nil
	}
}

// WithReadTimeout sets the read timeout for the http server.
func WithReadTimeout(timeout time.Duration) Option {
	return func(s *Server) error {
		s.readTimeout = timeout

		return nil
	}
}

// WithJwtToken sets the jwt token for the authentication middleware.
func WithJwtToken(token jwt.Claims) Option {
	return func(s *Server) error {
		s.jwtToken = token

		return nil
	}
}

// WithMTLSConfig sets the mTLS configuration for the server. This requires client certificates signed by a ca from the
// pool and will serve with the given Certificate.
func WithMTLSConfig(pool *x509.CertPool, server *tls.Certificate) Option {
	return func(s *Server) error {
		s.tls = &tls.Config{
			MinVersion:   tls.VersionTLS12,
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    pool,
			Certificates: []tls.Certificate{*server},
		}

		return nil
	}
}

// WithEmbeddedMetricsEndpoint enables the prometheus metrics on the /metrics endpoint. Please note that when using
// a custom http handler this option will not be applied successfully.
func WithEmbeddedMetricsEndpoint() Option {
	return func(s *Server) error {
		s.GET("/metrics", gin.WrapH(promhttp.Handler()))

		return nil
	}
}

// NewServer creates a new instance of the server.
func NewServer(opts ...Option) (*Server, error) {
	server := initializeServer()

	// First apply the options to the server - afterwards we will only configure what was not configured before
	for _, opt := range opts {
		if err := opt(server); err != nil {
			return nil, err
		}
	}

	if server.grpc == nil {
		middleware := NewAuthenticationMiddleware(server.jwtKeyFunc, server.jwtToken)

		unaryInt := grpc.ChainUnaryInterceptor(
			otelgrpc.UnaryServerInterceptor(),
			selector.UnaryServerInterceptor(middleware.UnaryServerInterceptor(), selector.MatchFunc(server.matchFunc)),
			recovery.UnaryServerInterceptor(recovery.WithRecoveryHandler(server.panicRecoveryHandler)),
		)
		streamInt := grpc.ChainStreamInterceptor(
			otelgrpc.StreamServerInterceptor(),
			selector.StreamServerInterceptor(middleware.StreamServerInterceptor(), selector.MatchFunc(server.matchFunc)),
			recovery.StreamServerInterceptor(recovery.WithRecoveryHandler(server.panicRecoveryHandler)),
		)

		server.grpc = grpc.NewServer(unaryInt, streamInt)

		server.healthcheck = health.NewServer()
		healthgrpc.RegisterHealthServer(server.grpc, server.healthcheck)
	}

	if server.grpcweb == nil && !server.grpcWebDisabled {
		server.grpcweb = grpcweb.WrapServer(server.grpc)
	}

	if server.http == nil {
		server.http = server.Engine.Handler()
		server.GET("/ping", func(context *gin.Context) {
			context.String(http.StatusOK, "pong")
		})
	}

	if server.server == nil {
		server.server = prepareServer(server)
	}

	return server, nil
}

func (s *Server) matchFunc(_ context.Context, callMeta interceptors.CallMeta) bool {
	return healthgrpc.Health_ServiceDesc.ServiceName != callMeta.Service || !s.insecureHealth
}

func initializeServer() *Server {
	gin.SetMode(gin.ReleaseMode)
	server := &Server{
		Engine:          gin.New(),
		tls:             nil,
		grpcWebDisabled: false,
		grpcweb:         nil,
		grpc:            nil,
		http:            nil,
		server:          nil,
		healthcheck:     nil,
		readTimeout:     defaultReadTimeout,
		jwtKeyFunc:      nil,
		jwtToken:        nil,
		insecureHealth:  false,
	}
	server.Use(logger.NewGinLogger())
	server.Use(gin.Recovery())

	return server
}

func prepareServer(server *Server) *http.Server {
	return &http.Server{
		Addr:              "",
		Handler:           nil,
		TLSConfig:         server.tls,
		ReadTimeout:       server.readTimeout,
		ReadHeaderTimeout: 0,
		WriteTimeout:      0,
		IdleTimeout:       0,
		MaxHeaderBytes:    0,
		TLSNextProto:      nil,
		ConnState:         nil,
		ErrorLog:          logger.NewHTTPErrorLogger(),
		BaseContext:       nil,
		ConnContext:       nil,
	}
}

func (s *Server) panicRecoveryHandler(p any) error {
	log.Error().Any("panic", p).Stack().Msg("panic recovered")

	return status.Error(codes.Internal, "internal server error")
}

// RegisterService implements the grpc.ServiceRegistrar interface used to register services with the grpc server.
// ServiceRegistrar wraps a single method that supports service registration. It enables users to pass concrete types
// other than grpc.Server to the service registration methods exported by the IDL generated code.
func (s *Server) RegisterService(desc *grpc.ServiceDesc, impl interface{}) {
	s.grpc.RegisterService(desc, impl)
}

// ServeHTTP implements the http.Handler interface used internally to route requests to the correct handler. This
// function handles the selection of the correct handler (grpc, grpc-web or http) based on the content-type header.
func (s *Server) ServeHTTP(resp http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodPost {
		if strings.HasPrefix(req.Header.Get("content-type"), grpcWebContentType) && s.grpcweb != nil {
			s.grpcweb.ServeHTTP(resp, req)

			return
		}

		if strings.HasPrefix(req.Header.Get("content-type"), grpcContentType) {
			s.grpc.ServeHTTP(resp, req)

			return
		}
	}

	// Fall through to HTTP
	s.http.ServeHTTP(resp, req)
}

// SetServingStatus is called when need to reset the serving status of a service or insert a new service entry into
// the statusMap.
func (s *Server) SetServingStatus(service string, status healthgrpc.HealthCheckResponse_ServingStatus) {
	s.healthcheck.SetServingStatus(service, status)
}

// Serve starts the server on the given listener. It will automatically detect if the server is configured to use TLS.
func (s *Server) Serve(listener net.Listener) error {
	if s.tls == nil {
		s.server.Handler = h2c.NewHandler(s, &http2.Server{
			MaxHandlers:                  0,
			MaxConcurrentStreams:         0,
			MaxDecoderHeaderTableSize:    0,
			MaxEncoderHeaderTableSize:    0,
			MaxReadFrameSize:             0,
			PermitProhibitedCipherSuites: false,
			IdleTimeout:                  0,
			MaxUploadBufferPerConnection: 0,
			MaxUploadBufferPerStream:     0,
			NewWriteScheduler:            nil,
			CountError:                   nil,
		})
		err := s.server.Serve(listener)

		return fmt.Errorf("failed to serve: %w", err)
	}

	s.server.Handler = s
	err := s.server.ServeTLS(listener, "", "")

	return fmt.Errorf("failed to serve: %w", err)
}
