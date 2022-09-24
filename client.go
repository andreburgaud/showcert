package main

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

func printTLSDetails(state tls.ConnectionState) {
	// Display some info about the TLS connection
	_, _ = fmt.Fprintf(os.Stderr, "TLS Version  : %s\n", TLSVersionToString(state.Version))
	_, _ = fmt.Fprintf(os.Stderr, "Cipher Suite : %s\n", tls.CipherSuiteName(state.CipherSuite))
	_, _ = fmt.Fprintf(os.Stderr, "Server Name  : %s\n", state.ServerName)
}

func getRemoteCerts(domain string, verif bool) ([][]*x509.Certificate, error) {
	var host, port string

	var err error
	if host, port, err = net.SplitHostPort(domain); err != nil {
		host = domain
		port = "443"
	}

	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second},
		"tcp", net.JoinHostPort(host, port),
		&tls.Config{
			InsecureSkipVerify: !verif,
			MinVersion:         tls.VersionTLS10, // Intentional to test SSL
		})
	if err != nil {
		return nil, err
	}
	defer func(conn *tls.Conn) {
		_ = conn.Close()
	}(conn)

	// Test
	if err := conn.VerifyHostname(host); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Error while verifying the hostname: %s\n", err)
	} else {
		_, _ = fmt.Fprintf(os.Stderr, "Hostname %s verification successful\n", host)
	}

	var chains [][]*x509.Certificate

	state := conn.ConnectionState()
	printTLSDetails(state)

	if verif {
		//fmt.Println(">>> Verified Chains")
		verifiedChains := state.VerifiedChains
		//fmt.Printf("Received %d chains\n", len(verifiedChains))
		//fmt.Println(verifiedChains)
		if verifiedChains != nil && len(verifiedChains) > 0 {
			chains = verifiedChains
		} else {
			_, _ = fmt.Println("no verified certificates, trying peers")
		}
	} else {
		//fmt.Println(">>> Peer Certificates")
		chains = append(chains, state.PeerCertificates)
		//fmt.Printf("Received %d certificates\n", len(chains[0]))
		if len(chains[0]) == 0 {
			return nil, errors.New("no peer certificates received")
		}
	}
	return chains, nil
}

// getLocalCert builds and return an SSL Certificate object given a valid cert file (PEM format)
func getLocalCert(certFile string) (*x509.Certificate, error) {

	// Open and read PEM file
	data, err := os.ReadFile(certFile)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		_, _ = fmt.Printf("rest of PEM file content: %x", rest)
		return nil, fmt.Errorf("bad PEM file %s", certFile)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	return cert, nil
}
