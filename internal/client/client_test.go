package client

import (
	"testing"
)

// Test the GetLocalCerts function to ensure that the resulting certs contains a proper slice of *x509.Certificate
func TestGetLocalCerts(t *testing.T) {
	tt := []struct {
		certFile string
		expected string // serialNumber
	}{
		{"../../test_data/rsa_2048_exp3.crt", "689353446962534075818318094020409231943178713332"},
		{"../../test_data/rsa_4096_exp9.crt", "491857893787078309585312564136279056496696784059"},
		{"../../test_data/ecdsa.crt", "161666955289179666643937194263860491865277586603"},
		{"../../test_data/ed25519.crt", "170414627618143861399763465404232742787060139745"},
	}
	for _, tc := range tt {
		t.Run(tc.certFile, func(t *testing.T) {
			certs, err := GetLocalCerts(tc.certFile)
			if err != nil {
				t.Errorf("error creating cert from local pem file %s: %s", tc.certFile, err)
			}
			got := certs[0].SerialNumber.String()
			if got != tc.expected {
				t.Errorf("got %s, expected %s", got, tc.expected)
			}
		})
	}
}
