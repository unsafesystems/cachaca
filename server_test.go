//nolint
package cachaca

import (
	"context"
	"fmt"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestServer_DisableGrpcWeb(t *testing.T) {
	s, err := NewServer(DisableGrpcWeb())
	assert.Nil(t, err)
	assert.Nil(t, s.grpcweb)
}

func TestServer_FaultyOption(t *testing.T) {
	_, err := NewServer(func(s *Server) error {
		return fmt.Errorf("error")
	})
	assert.NotNil(t, err)
}

func TestServer_ReadTimeout(t *testing.T) {
	s, err := NewServer(WithReadTimeout(time.Second))
	assert.Nil(t, err)
	assert.Equal(t, time.Second, s.readTimeout)
}

func TestServer(t *testing.T) {
	suite.Run(t, new(ServerTestSuite))
}

type ServerTestSuite struct {
	suite.Suite
	server   *Server
	listener net.Listener
	port     int
	client   *grpc.ClientConn
}

func (s *ServerTestSuite) SetupSuite() {
	zerolog.SetGlobalLevel(zerolog.Disabled)

	server, err := NewServer(
		WithInsecureHealth(),
		WithEmbeddedMetricsEndpoint(),
	)
	require.Nil(s.T(), err)
	s.server = server

	l, err := net.Listen("tcp", fmt.Sprintf(":%d", 0))
	require.Nil(s.T(), err)

	go func() {
		err := s.server.Serve(l)
		if err != nil {
			panic(err)
		}
	}()

	s.listener = l
	s.port = l.Addr().(*net.TCPAddr).Port

	client, err := grpc.Dial(fmt.Sprintf("localhost:%d", s.port), grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.Nil(s.T(), err)

	s.client = client
}

func (s *ServerTestSuite) TestServer_WithoutTls() {
	// REST call to basically anything should return an unimplemented error
	response, err := http.Get(fmt.Sprintf("http://localhost:%d", s.port))
	assert.Nil(s.T(), err)
	assert.Equal(s.T(), http.StatusNotFound, response.StatusCode)
}

func (s *ServerTestSuite) TestServer_HealthCheck() {
	healthClient := healthpb.NewHealthClient(s.client)
	resp, err := healthClient.Check(context.Background(), &healthpb.HealthCheckRequest{
		Service: "",
	})
	require.Nil(s.T(), err)
	assert.Equal(s.T(), healthpb.HealthCheckResponse_SERVING, resp.Status)
}

func (s *ServerTestSuite) TestServer_SetServingStatus() {
	s.server.SetServingStatus("", healthpb.HealthCheckResponse_NOT_SERVING)

	healthClient := healthpb.NewHealthClient(s.client)
	resp, err := healthClient.Check(context.Background(), &healthpb.HealthCheckRequest{
		Service: "",
	})
	require.Nil(s.T(), err)
	assert.Equal(s.T(), healthpb.HealthCheckResponse_NOT_SERVING, resp.Status)

	s.server.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
}

func (s *ServerTestSuite) TestServer_HealthCheckUnknown() {
	healthClient := healthpb.NewHealthClient(s.client)
	resp, err := healthClient.Check(context.Background(), &healthpb.HealthCheckRequest{
		Service: "test",
	})
	require.NotNil(s.T(), err)
	assert.Nil(s.T(), resp)
	assert.Equal(s.T(), codes.NotFound, status.Code(err))
}

func (s *ServerTestSuite) TestServer_EmbeddedMetrics() {
	response, err := http.Get(fmt.Sprintf("http://localhost:%d/metrics", s.port))
	assert.Nil(s.T(), err)
	assert.Equal(s.T(), http.StatusOK, response.StatusCode)
}

func (s *ServerTestSuite) TestServer_Ping() {
	response, err := http.Get(fmt.Sprintf("http://localhost:%d/ping", s.port))
	assert.Nil(s.T(), err)
	assert.Equal(s.T(), http.StatusOK, response.StatusCode)
	resp, err := io.ReadAll(response.Body)
	assert.Nil(s.T(), err)
	assert.Equal(s.T(), "pong", string(resp))
}
