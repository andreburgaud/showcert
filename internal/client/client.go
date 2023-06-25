package client

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"time"
)

func TLSVersionToString(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "1.0"
	case tls.VersionTLS11:
		return "1.1"
	case tls.VersionTLS12:
		return "1.2"
	case tls.VersionTLS13:
		return "1.3"
	}
	return fmt.Sprintf("Unknown TLS version %d", v)
}

// Response contains TLS connection metadata and the list of chains containing list of certificate
type Response struct {
	TlsVersion        string
	CipherSuite       string
	HostVerification  bool
	CertificateChains [][]*x509.Certificate
}

// pemToCertPool takes a PEM file and returns a CertPool used to add self-signed Root CAs to the client
func pemToCertPool(cafile string) (*x509.CertPool, error) {
	certPool := x509.NewCertPool()
	data, err := os.ReadFile(cafile)
	if err != nil {
		return nil, err
	}
	certPool.AppendCertsFromPEM(data)
	return certPool, nil
}

// GetRemoteCerts returns one or more certificate chains from a TLS server
func GetRemoteCerts(domain string, verify bool, cafile string) (Response, error) {
	var host, port string

	var err error
	if host, port, err = net.SplitHostPort(domain); err != nil {
		host = domain
		port = "443"
	}

	config := &tls.Config{
		InsecureSkipVerify: !verify,
		MinVersion:         tls.VersionTLS10, // Intentional to test SSL
	}

	if len(cafile) > 0 {
		cp, err := pemToCertPool(cafile)
		if err != nil {
			return Response{}, err
		}
		config.RootCAs = cp
	}

	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second},
		"tcp", net.JoinHostPort(host, port), config)

	if err != nil {
		return Response{}, err
	}
	defer func(conn *tls.Conn) {
		_ = conn.Close()
	}(conn)

	hostVerification := true
	if err := conn.VerifyHostname(host); err != nil {
		hostVerification = false
	}
	var chains [][]*x509.Certificate

	state := conn.ConnectionState()

	if verify {
		verifiedChains := state.VerifiedChains
		if verifiedChains != nil && len(verifiedChains) > 0 {
			chains = verifiedChains
		} else {
			_, _ = fmt.Println("no verified certificates, trying peers")
		}
	} else {
		chains = append(chains, state.PeerCertificates)
		if len(chains[0]) == 0 {
			return Response{}, errors.New("no peer certificates received")
		}
	}
	return Response{
		TlsVersion:        TLSVersionToString(state.Version),
		CipherSuite:       tls.CipherSuiteName(state.CipherSuite),
		HostVerification:  hostVerification,
		CertificateChains: chains,
	}, nil
}

// GetLocalCerts builds and return an array of SSL Certificates given a valid cert file (PEM format)
func GetLocalCerts(certFile string) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	// Open and read PEM file
	data, err := os.ReadFile(certFile)
	if err != nil {
		return nil, err
	}
	for {
		block, rest := pem.Decode(data)
		if block == nil || block.Type != "CERTIFICATE" {
			_, _ = fmt.Printf("rest of PEM file content: %x", rest)
			return nil, fmt.Errorf("bad PEM file %s", certFile)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
		if len(rest) == 0 {
			break
		}
		data = rest
	}
	return certs, nil
}
