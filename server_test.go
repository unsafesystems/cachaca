//nolint
package cachaca

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/golang/protobuf/proto"
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

func TestServer_WithJwtKeyFunc(t *testing.T) {
	fn := func(*jwt.Token) (interface{}, error) {
		return "ok", nil
	}

	s, err := NewServer(WithJwtKeyFunc(fn))
	assert.Nil(t, err)
	v, _ := s.jwtKeyFunc(nil)
	assert.Equal(t, "ok", v.(string)) // Testing for function equality doesn't work
}

func TestServer_WithJwtToken(t *testing.T) {
	s, err := NewServer(WithJwtToken(jwt.StandardClaims{}))
	assert.Nil(t, err)
	assert.Equal(t, jwt.StandardClaims{}, s.jwtToken)
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

func makeGrpcWebRequest(t *testing.T, payload proto.Message) io.Reader {
	data, err := proto.Marshal(payload)
	require.Nil(t, err)

	header := make([]byte, 5)
	binary.BigEndian.PutUint32(header[1:], uint32(len(data)))
	buf := bytes.NewBuffer(header)
	buf.Write(data)

	return buf
}

func parseGrpcWebResponse(t *testing.T, resp *http.Response, payload proto.Message) {
	data, err := io.ReadAll(resp.Body)
	require.Nil(t, err)

	l := binary.BigEndian.Uint32(data[1:5])
	data = data[5 : l+5]

	require.Nil(t, proto.Unmarshal(data, payload))
}

func (s *ServerTestSuite) TestServer_GrpcWeb() {
	payload := &healthpb.HealthCheckRequest{Service: ""}
	buf := makeGrpcWebRequest(s.T(), payload)

	req, err := http.NewRequest("POST", fmt.Sprintf("http://localhost:%d/grpc.health.v1.Health/Check", s.port), buf)
	require.Nil(s.T(), err)

	req.Header.Set("Content-Type", "application/grpc-web")

	client := &http.Client{}
	resp, err := client.Do(req)
	require.Nil(s.T(), err)

	assert.Equal(s.T(), http.StatusOK, resp.StatusCode)
	assert.Equal(s.T(), "application/grpc-web", resp.Header.Get("Content-Type"))

	response := new(healthpb.HealthCheckResponse)
	parseGrpcWebResponse(s.T(), resp, response)
	assert.Equal(s.T(), healthpb.HealthCheckResponse_SERVING, response.Status)
}
