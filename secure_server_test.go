//nolint
package cachaca

import (
	"bytes"
	"cachaca/internal/helloworld"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"io"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

func TestSecureServer(t *testing.T) {
	suite.Run(t, new(SecureServerTestSuite))
}

type SecureServerTestSuite struct {
	suite.Suite
	server   *Server
	listener net.Listener
	port     int
	client   *grpc.ClientConn
	certs    *certificates
}

func (s *SecureServerTestSuite) SetupSuite() {
	zerolog.SetGlobalLevel(zerolog.Disabled)

	certs := getCertificates(s.T())

	server, err := NewServer(
		WithMTLSConfig(certs.caPool, certs.serverCert),
	)
	require.Nil(s.T(), err)

	helloworld.RegisterHelloWorldServer(server, &helloworld.Service{})
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

	clientTlsConfig := &tls.Config{
		RootCAs:      certs.caPool,
		Certificates: []tls.Certificate{*certs.clientCert},
	}
	client, err := grpc.Dial(fmt.Sprintf("localhost:%d", s.port), grpc.WithTransportCredentials(credentials.NewTLS(clientTlsConfig)))
	require.Nil(s.T(), err)

	s.client = client
	s.certs = certs
}

func (s *SecureServerTestSuite) TestServer_SecurePing() {
	config := &tls.Config{
		Certificates: []tls.Certificate{
			*s.certs.clientCert,
		},
		RootCAs: s.certs.caPool,
	}
	client := http.Client{
		Transport: &http.Transport{
			TLSClientConfig: config,
		},
	}
	response, err := client.Get(fmt.Sprintf("https://localhost:%d/ping", s.port))
	require.Nil(s.T(), err)
	assert.Equal(s.T(), http.StatusOK, response.StatusCode)
	resp, err := io.ReadAll(response.Body)
	require.Nil(s.T(), err)
	assert.Equal(s.T(), "pong", string(resp))
}

func (s *SecureServerTestSuite) TestServer_PingNoTlsFail() {
	config := &tls.Config{
		RootCAs: s.certs.caPool,
	}
	client := http.Client{
		Transport: &http.Transport{
			TLSClientConfig: config,
		},
	}
	_, err := client.Get(fmt.Sprintf("https://localhost:%d/ping", s.port))
	require.NotNil(s.T(), err)
}

func (s *SecureServerTestSuite) TestServer_PingWrongCertFail() {
	config := &tls.Config{
		Certificates: []tls.Certificate{
			*s.certs.invalidClientCert,
		},
		RootCAs: s.certs.caPool,
	}
	client := http.Client{
		Transport: &http.Transport{
			TLSClientConfig: config,
		},
	}
	_, err := client.Get(fmt.Sprintf("https://localhost:%d/ping", s.port))
	require.NotNil(s.T(), err)
}

func (s *SecureServerTestSuite) TestServer_HealthCheck() {
	healthClient := healthpb.NewHealthClient(s.client)
	resp, err := healthClient.Check(context.Background(), &healthpb.HealthCheckRequest{
		Service: "",
	})
	require.Nil(s.T(), err)
	assert.Equal(s.T(), healthpb.HealthCheckResponse_SERVING, resp.Status)
}

func (s *SecureServerTestSuite) TestServer_GrpcPing() {
	pingClient := helloworld.NewHelloWorldClient(s.client)
	resp, err := pingClient.Ping(context.Background(), &helloworld.PingRequest{
		Message: "ping",
	})

	require.Nil(s.T(), err, fmt.Sprintf("%+v", err))
	assert.Equal(s.T(), "pong", resp.Message)
}

func (s *SecureServerTestSuite) TestServer_CommonName() {
	pingClient := helloworld.NewHelloWorldClient(s.client)
	resp, err := pingClient.CommonName(context.Background(), &helloworld.CommonNameRequest{})

	require.Nil(s.T(), err, fmt.Sprintf("%+v", err))
	assert.Equal(s.T(), "client1", resp.CommonName)
}

func (s *SecureServerTestSuite) TestServer_Panic() {
	pingClient := helloworld.NewHelloWorldClient(s.client)
	_, err := pingClient.Panic(context.Background(), &helloworld.PanicRequest{})

	require.NotNil(s.T(), err, fmt.Sprintf("%+v", err))
	assert.Equal(s.T(), codes.Internal, status.Code(err))
}

type certificates struct {
	caPool            *x509.CertPool
	serverCert        *tls.Certificate
	clientCert        *tls.Certificate
	invalidClientCert *tls.Certificate
}

func getCertificates(t *testing.T) *certificates {
	caCert, caPrivKey, caPEM := createCACertificate(t)
	serverPEM, serverPrivPEM := createCertificate(t, 1567, "server", caCert, caPrivKey)
	clientPEM, clientPrivPEM := createCertificate(t, 1568, "client1", caCert, caPrivKey)

	caCert2, caPrivKey2, _ := createCACertificate(t)
	invalidClientPEM, invalidClientPrivPEM := createCertificate(t, 1569, "client2", caCert2, caPrivKey2)

	serverCert, err := tls.X509KeyPair(serverPEM.Bytes(), serverPrivPEM.Bytes())
	require.Nil(t, err)

	clientCert, err := tls.X509KeyPair(clientPEM.Bytes(), clientPrivPEM.Bytes())
	require.Nil(t, err)

	invalidClientCert, err := tls.X509KeyPair(invalidClientPEM.Bytes(), invalidClientPrivPEM.Bytes())
	require.Nil(t, err)

	caPool := x509.NewCertPool()
	ok := caPool.AppendCertsFromPEM(caPEM.Bytes())
	require.True(t, ok)

	return &certificates{
		caPool:            caPool,
		serverCert:        &serverCert,
		clientCert:        &clientCert,
		invalidClientCert: &invalidClientCert,
	}
}

func createCACertificate(t *testing.T) (*x509.Certificate, *rsa.PrivateKey, *bytes.Buffer) {
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization:  []string{"Company, INC."},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{"Golden Gate Bridge"},
			PostalCode:    []string{"94016"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	caPrivKey, err := rsa.GenerateKey(rand.Reader, 1024)
	require.Nil(t, err)

	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	require.Nil(t, err)

	caPEM := new(bytes.Buffer)
	_ = pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})

	return ca, caPrivKey, caPEM
}

func createCertificate(t *testing.T, serialNumber int64, commonName string, ca *x509.Certificate, caPrivKey *rsa.PrivateKey) (*bytes.Buffer, *bytes.Buffer) {
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(serialNumber),
		Subject: pkix.Name{
			CommonName:    commonName,
			Organization:  []string{"Company, INC."},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{"Golden Gate Bridge"},
			PostalCode:    []string{"94016"},
		},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	certPrivKey, err := rsa.GenerateKey(rand.Reader, 1024)
	require.Nil(t, err)

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, ca, &certPrivKey.PublicKey, caPrivKey)
	require.Nil(t, err)

	return pemFromBytes(certBytes, certPrivKey)
}

func pemFromBytes(certBytes []byte, certPrivKey *rsa.PrivateKey) (*bytes.Buffer, *bytes.Buffer) {
	certPEM := new(bytes.Buffer)
	_ = pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	certPrivKeyPEM := new(bytes.Buffer)
	_ = pem.Encode(certPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certPrivKey),
	})

	return certPEM, certPrivKeyPEM
}
