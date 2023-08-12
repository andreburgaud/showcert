package client

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
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
func pemToCertPool(cp *x509.CertPool, cafile string) error {
	data, err := os.ReadFile(cafile)
	if err != nil {
		return err
	}
	cp.AppendCertsFromPEM(data)
	return nil
}

// dirToCertPool loads all the PEM files in a directory and returns a CertPool
func dirToCertPool(certPool *x509.CertPool, cadir string) error {
	files, err := os.ReadDir(cadir)
	if err != nil {
		return err
	}
	for _, file := range files {
		if file.IsDir() {
			continue
		}
		if err := pemToCertPool(certPool, filepath.Join(cadir, file.Name())); err != nil {
			return err
		}
	}
	return nil
}

// GetRemoteCerts returns one or more certificate chains from a TLS server
func GetRemoteCerts(verify bool, host, port, cafile, cadir string) (Response, error) {

	config := &tls.Config{
		InsecureSkipVerify: !verify,
		MinVersion:         tls.VersionTLS10, // Intentional to test SSL
	}

	var cp *x509.CertPool

	if len(cafile) > 0 {
		cp = x509.NewCertPool()
		if err := pemToCertPool(cp, cafile); err != nil {
			return Response{}, err
		}
	}

	if len(cadir) > 0 {
		if cp == nil {
			cp = x509.NewCertPool()
		}
		if err := dirToCertPool(cp, cadir); err != nil {
			return Response{}, err
		}
	}

	if cp != nil {
		config.RootCAs = cp
	}

	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second},
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
		if len(verifiedChains) > 0 {
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
