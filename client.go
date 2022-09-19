package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"time"
)

func getRemoteCerts(domain string, verif bool) ([][]*x509.Certificate, error) {
	var host, port string

	var err error
	if host, port, err = net.SplitHostPort(domain); err != nil {
		host = domain
		port = "443"
	}

	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second},
		"tcp", net.JoinHostPort(host, port),
		&tls.Config{InsecureSkipVerify: !verif})
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Test
	if err := conn.VerifyHostname(host); err != nil {
		fmt.Fprintf(os.Stderr, "Error while verifying the hostname: %s\n", err)
	} else {
		fmt.Fprintf(os.Stderr, "Hostname %s verification successful\n", host)
	}

	var chains [][]*x509.Certificate

	if verif {
		//fmt.Println(">>> Verified Chains")
		verifiedChains := conn.ConnectionState().VerifiedChains
		//fmt.Printf("Received %d chains\n", len(verifiedChains))
		//fmt.Println(verifiedChains)
		if verifiedChains != nil && len(verifiedChains) > 0 {
			chains = verifiedChains
		} else {
			fmt.Println("no verified certificates, trying peers")
		}
	} else {
		//fmt.Println(">>> Peer Certificates")
		chains = append(chains, conn.ConnectionState().PeerCertificates)
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
	data, err := ioutil.ReadFile(certFile)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		fmt.Printf("Rest of PEM file content: %x", rest)
		return nil, fmt.Errorf("Bad PEM file %s", certFile)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	return cert, nil
}
