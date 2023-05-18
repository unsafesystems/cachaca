//nolint
package cert_gen

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type Certificates struct {
	CAPool            *x509.CertPool
	ServerCert        *tls.Certificate
	ClientCert        *tls.Certificate
	InvalidClientCert *tls.Certificate
}

func GenerateMockCertificates(t *testing.T) *Certificates {
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

	return &Certificates{
		CAPool:            caPool,
		ServerCert:        &serverCert,
		ClientCert:        &clientCert,
		InvalidClientCert: &invalidClientCert,
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
