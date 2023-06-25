package cert

import (
	"encoding/base64"
	"fmt"
	"math/big"
	"os"
	"strings"
	"testing"

	"showcert/internal/client"
)

func TestIntToHex(t *testing.T) {
	tt := []struct {
		n        string
		expected string
	}{
		{"0", "00"},
		{"5", "05"},
		{"16", "10"},
		{"10", "0A"},
		{"55618078722282788371078261976750506447", "29:D7:A6:FE:D7:18:64:45:0A:06:8F:C4:70:0E:41:CF"},
		{"5618078722282788371078261976750506447", "04:3A:00:AA:A9:D5:02:08:05:41:7E:A4:70:0E:41:CF"},
	}
	for _, tc := range tt {
		desc := fmt.Sprintf("intToHex(%s)", tc.n)
		t.Run(desc, func(t *testing.T) {
			i, ok := new(big.Int).SetString(tc.n, 10)
			if !ok {
				t.Errorf("error creating big int with value %s", tc.n)
			}
			got := intToHex(i)
			if got != tc.expected {
				t.Errorf("got %s, expected %s", got, tc.expected)
			}
		})
	}
}

// b64ToBytes is a helper function allowing to define tests taking base64 encoded byte buffers as argument
// like TestBytesToHex for example
func b64ToBytes(b64 string) ([]byte, error) {
	dst := make([]byte, base64.StdEncoding.DecodedLen(len(b64)))
	n, err := base64.StdEncoding.Decode(dst, []byte(b64))
	if err != nil {
		return nil, err
	}
	return dst[:n], nil
}

func TestBytesToHex(t *testing.T) {
	tt := []struct {
		b64      string
		expected string
	}{
		{"SGVsbG8h", "48:65:6C:6C:6F:21"},
		{"c2hvd2NlcnQ=", "73:68:6F:77:63:65:72:74"},
		{
			"ZMVy7yWkZVsDkLDvGqfn0Nq95dBIKiKrEEUtpL4Uklru+BtZavGj/KpT",
			"64:C5:72:EF:25:A4:65:5B:03:90:B0:EF:1A:A7:E7:D0:DA:BD:E5:D0:48:2A:22:AB:10:45:2D:A4:BE:14:92:5A:EE:F8:1B:59:6A:F1:A3:FC:AA:53",
		},
		{
			"UxWZtfdbayqL3tfphH7K9Mut9OgwmuXFX5z77cV8gNqExh1CkWEUUWF1KLm1q5LPqttPlwWnez8iOeJECgflhSqvxPlipFzGi65hRn/8HqvP+a3EfMEIFZiz7HWRuxEoTKszeg==",
			"53:15:99:B5:F7:5B:6B:2A:8B:DE:D7:E9:84:7E:CA:F4:CB:AD:F4:E8:30:9A:E5:C5:5F:9C:FB:ED:C5:7C:80:DA:84:C6:1D:42:91:61:14:51:61:75:28:B9:B5:AB:92:CF:AA:DB:4F:97:05:A7:7B:3F:22:39:E2:44:0A:07:E5:85:2A:AF:C4:F9:62:A4:5C:C6:8B:AE:61:46:7F:FC:1E:AB:CF:F9:AD:C4:7C:C1:08:15:98:B3:EC:75:91:BB:11:28:4C:AB:33:7A",
		},
	}
	for _, tc := range tt {
		t.Run(tc.b64, func(t *testing.T) {
			dst, err := b64ToBytes(tc.b64)
			if err != nil {
				t.Errorf("error processing b64 %s: %s", tc.b64, err)
			}
			got := bytesToHex(dst)
			if got != tc.expected {
				t.Errorf("got %s, expected %s", got, tc.expected)
			}
		})
	}
}

// Test the encodePem function by comparing the result of the initial raw content from the local PEM test file and the
// construction of the PEM string, from the same file.
func TestEncodePem(t *testing.T) {
	tt := []struct {
		certFile string
	}{
		{"../../test_data/rsa_2048_exp3.crt"},
		{"../../test_data/rsa_4096_exp9.crt"},
		{"../../test_data/ecdsa.crt"},
		{"../../test_data/ed25519.crt"},
	}
	for _, tc := range tt {
		t.Run(tc.certFile, func(t *testing.T) {
			data, err := os.ReadFile(tc.certFile)
			if err != nil {
				t.Errorf("error reading local cert %s: %s", tc.certFile, err)
			}
			expected := strings.TrimSpace(string(data))
			certs, err := client.GetLocalCerts(tc.certFile)
			if err != nil {
				t.Errorf("error creating cert from local pem file %s: %s", tc.certFile, err)
			}
			got := strings.TrimSpace(encodePem(certs[0]))
			if got != expected {
				t.Errorf("got %s, expected %s", got, expected)
			}
		})
	}
}
