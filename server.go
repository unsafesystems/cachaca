package cachaca

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/recovery"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/selector"
	"github.com/improbable-eng/grpc-web/go/grpcweb"
	"github.com/rs/zerolog/log"
	"github.com/unsafesystems/cachaca/auth"
	"github.com/unsafesystems/cachaca/internal/logger"
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
	TLSConfig       *tls.Config
	GrpcWebDisabled bool
	GrpcWeb         *grpcweb.WrappedGrpcServer
	Grpc            *grpc.Server
	HTTPHandler     http.Handler
	Server          *http.Server
	Healthcheck     *health.Server

	ReadTimeout    time.Duration
	InsecureHealth bool
	Authorizer     auth.Authorizer
}

// NewServer creates a new instance of the server.
func NewServer(opts ...Option) (*Server, error) {
	gin.SetMode(gin.ReleaseMode)
	server := &Server{
		Engine:          gin.New(),
		GrpcWebDisabled: false,
		ReadTimeout:     defaultReadTimeout,
		InsecureHealth:  false,
	}

	// First apply the options to the server - afterward we will only configure what was not configured before
	for _, opt := range opts {
		if err := opt.Apply(server); err != nil {
			return nil, fmt.Errorf("failed applying option: %w", err)
		}
	}

	// Middleware to authenticate requests (both grpc and http)
	middleware := newMiddleware(server.Authorizer)

	// Prepare the gin server with middlewares
	server.Use(logger.NewGinLogger())
	server.Use(gin.Recovery())
	server.Use(middleware.ginMiddleware)

	if server.Grpc == nil {
		unaryInt := grpc.ChainUnaryInterceptor(
			otelgrpc.UnaryServerInterceptor(),
			selector.UnaryServerInterceptor(middleware.unaryServerInterceptor(), selector.MatchFunc(server.matchFunc)),
			recovery.UnaryServerInterceptor(recovery.WithRecoveryHandler(server.panicRecoveryHandler)),
		)
		streamInt := grpc.ChainStreamInterceptor(
			otelgrpc.StreamServerInterceptor(),
			selector.StreamServerInterceptor(middleware.streamServerInterceptor(), selector.MatchFunc(server.matchFunc)),
			recovery.StreamServerInterceptor(recovery.WithRecoveryHandler(server.panicRecoveryHandler)),
		)

		server.Grpc = grpc.NewServer(unaryInt, streamInt)

		server.Healthcheck = health.NewServer()
		healthgrpc.RegisterHealthServer(server.Grpc, server.Healthcheck)
	}

	if server.GrpcWeb == nil && !server.GrpcWebDisabled {
		server.GrpcWeb = grpcweb.WrapServer(server.Grpc)
	}

	if server.HTTPHandler == nil {
		server.HTTPHandler = server.Engine.Handler()
	}

	if server.Server == nil {
		server.Server = &http.Server{
			TLSConfig:   server.TLSConfig,
			ReadTimeout: server.ReadTimeout,
			ErrorLog:    logger.NewHTTPErrorLogger(),
		}
	}

	return server, nil
}

func (s *Server) matchFunc(_ context.Context, callMeta interceptors.CallMeta) bool {
	return !(healthgrpc.Health_ServiceDesc.ServiceName == callMeta.Service && s.InsecureHealth)
}

func (s *Server) panicRecoveryHandler(p any) error {
	log.Error().Any("panic", p).Stack().Msg("panic recovered")

	return status.Error(codes.Internal, "internal server error")
}

// RegisterService implements the grpc.ServiceRegistrar interface used to register services with the grpc server.
// ServiceRegistrar wraps a single method that supports service registration. It enables users to pass concrete types
// other than grpc.Server to the service registration methods exported by the IDL generated code.
func (s *Server) RegisterService(desc *grpc.ServiceDesc, impl interface{}) {
	s.Grpc.RegisterService(desc, impl)
}

// ServeHTTP implements the http.Handler interface used internally to route requests to the correct handler. This
// function handles the selection of the correct handler (grpc, grpc-web or http) based on the content-type header.
func (s *Server) ServeHTTP(resp http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodPost {
		if strings.HasPrefix(req.Header.Get("content-type"), grpcWebContentType) && s.GrpcWeb != nil {
			s.GrpcWeb.ServeHTTP(resp, req)

			return
		}

		if strings.HasPrefix(req.Header.Get("content-type"), grpcContentType) {
			s.Grpc.ServeHTTP(resp, req)

			return
		}
	}

	// Fall through to HTTP
	s.HTTPHandler.ServeHTTP(resp, req)
}

// SetServingStatus is called when need to reset the serving status of a service or insert a new service entry into
// the statusMap.
func (s *Server) SetServingStatus(service string, status healthgrpc.HealthCheckResponse_ServingStatus) {
	s.Healthcheck.SetServingStatus(service, status)
}

// Serve starts the server on the given listener. It will automatically detect if the server is configured to use TLS.
func (s *Server) Serve(listener net.Listener) error {
	if s.TLSConfig == nil {
		s.Server.Handler = h2c.NewHandler(s, &http2.Server{})
		err := s.Server.Serve(listener)

		return fmt.Errorf("failed to serve: %w", err)
	}

	s.Server.Handler = s
	err := s.Server.ServeTLS(listener, "", "")

	return fmt.Errorf("failed to serve: %w", err)
}
