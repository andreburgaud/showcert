package cert

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"math/bits"
	"strings"
	"time"
)

// Chains contains a list of chains
type Chains struct {
	CertificateChains []CertificateChain `json:"chains"`
}

// CertificateChain contains a list of certificates
type CertificateChain struct {
	ChainNumber  string        `json:"chain_number"`
	Certificates []Certificate `json:"certificates"`
}

// Time includes specific human readable time values
type Time struct {
	CertTime  time.Time `json:"cert_time"`
	UnixTime  int64     `json:"unit_time"`
	LocalTime string    `json:"local_time"`
	UTCTime   string    `json:"utc_time"`
}

// parseTime parse a given time and populate a Time struct
func parseTime(t time.Time) Time {
	ct := Time{
		CertTime:  t,
		UnixTime:  t.Unix(),
		LocalTime: t.Local().Format("Monday, January 2, 2006 at 3:04:05 PM MST"),
		UTCTime:   t.Format("Monday, January 2, 2006 at 3:04:05 PM MST"),
	}
	return ct
}

// PublicKey contains the properties for all the supported key algorithm (RSA, ECDSA, missing Ed25519)
type PublicKey struct {
	PublicKeyAlgorithm string `json:"public_key_algorithm"`
	Exponent           int    `json:"exponent,omitempty"`
	ExponentBits       int    `json:"exponent_bits,omitempty"`
	Modulus            string `json:"modulus,omitempty"`
	ModulusBits        int    `json:"modulus_bits,omitempty"`
	Curve              string `json:"curve,omitempty"`
	X                  string `json:"x,omitempty"`
	XBits              int    `json:"x_bits,omitempty"`
	Y                  string `json:"y,omitempty"`
	YBits              int    `json:"y_bits,omitempty"`
}

// TODO: Ed25519
// parsePublicKey parses a cert public key and constructs a PublicKey
func parsePublicKey(key any, algo x509.PublicKeyAlgorithm) PublicKey {
	pk := PublicKey{
		PublicKeyAlgorithm: algo.String(),
	}
	switch algo {
	case x509.DSA:
		// Not supported
	case x509.Ed25519:
		// Not implemented yet
	case x509.RSA:
		rsaKey := key.(*rsa.PublicKey)
		pk.Exponent = rsaKey.E
		pk.ExponentBits = bits.Len32(uint32(rsaKey.E))
		pk.Modulus = intToHex(rsaKey.N)
		pk.ModulusBits = rsaKey.N.BitLen()
	case x509.ECDSA:
		ecdsaKey := key.(*ecdsa.PublicKey)
		pk.Curve = ecdsaKey.Curve.Params().Name
		pk.X = intToHex(ecdsaKey.X)
		pk.XBits = ecdsaKey.X.BitLen()
		pk.Y = intToHex(ecdsaKey.Y)
		pk.YBits = ecdsaKey.Y.BitLen()
	}
	return pk
}

// getKeyUsages return a list of string or usages
func getKeyUsage(usage x509.KeyUsage) []string {
	var usages []string
	if usage&x509.KeyUsageDigitalSignature > 0 {
		usages = append(usages, "Digital Signature")
	}
	if usage&x509.KeyUsageContentCommitment > 0 {
		usages = append(usages, "Content Commitment")
	}
	if usage&x509.KeyUsageKeyEncipherment > 0 {
		usages = append(usages, "Key Encipherment")
	}
	if usage&x509.KeyUsageDataEncipherment > 0 {
		usages = append(usages, "Data Encipherment")
	}
	if usage&x509.KeyUsageKeyAgreement > 0 {
		usages = append(usages, "Key Agreement")
	}
	if usage&x509.KeyUsageCertSign > 0 {
		usages = append(usages, "Cert Signature")
	}
	if usage&x509.KeyUsageCRLSign > 0 {
		usages = append(usages, "CRL Signature")
	}
	if usage&x509.KeyUsageEncipherOnly > 0 {
		usages = append(usages, "Encipher Only")
	}
	if usage&x509.KeyUsageDecipherOnly > 0 {
		usages = append(usages, "Decipher Only")
	}

	return usages
}

// Certificate represents a JSON description of an X.509 certificate.
// SAN: Subject Alternative Name (DNSNames in Golang x509 Certificate)
type Certificate struct {
	CertificateNumber     string    `json:"certificate_number"`
	Version               int       `json:"version,omitempty"`
	SerialNumber          string    `json:"serial_number,omitempty"`
	SerialNumberHex       string    `json:"serial_number_hex,omitempty"`
	Subject               Name      `json:"subject,omitempty"`
	DNSNames              []string  `json:"dns_names,omitempty"`
	IPAddresses           []string  `json:"ip_addresses,omitempty"`
	SubjectKeyId          string    `json:"subject_key_id"`
	Issuer                Name      `json:"issuer,omitempty"`
	NotBefore             Time      `json:"not_before"`
	NotAfter              Time      `json:"not_after"`
	SHA1Fingerprint       string    `json:"sha1_fingerprint"`
	SHA256Fingerprint     string    `json:"sha256_fingerprint"`
	OCSPServer            string    `json:"ocsp_server,omitempty"`
	AuthorityKeyId        string    `json:"authority_key_id,omitempty"`
	KeyUsage              string    `json:"key_usage"`
	CertPublicKey         PublicKey `json:"public_key,omitempty"`
	Signature             string    `json:"signature"`
	SignatureAlgorithm    string    `json:"signature_algorithm"`
	Ca                    bool      `json:"certificate_authority"`
	CRLDistributionPoints []string
	RawPEM                string `json:"pem"`
}

// Name represents a JSON description of a PKIX Name
type Name struct {
	CommonName         string        `json:"common_name,omitempty"`
	SerialNumber       string        `json:"serial_number,omitempty"`
	Country            string        `json:"country,omitempty"`
	Organization       string        `json:"organization,omitempty"`
	OrganizationalUnit string        `json:"organizational_unit,omitempty"`
	Locality           string        `json:"locality,omitempty"`
	Province           string        `json:"province,omitempty"`
	StreetAddress      string        `json:"street_address,omitempty"`
	PostalCode         string        `json:"postal_code,omitempty"`
	Names              []interface{} `json:"names,omitempty"`
	ExtraNames         []interface{} `json:"extra_names,omitempty"`
}

// bytesToHex convert a buffer of bytes to a string in hexadecimal format
func bytesToHex(buf []byte) string {
	var s string

	for i, c := range buf {
		if i > 0 {
			s += ":"
		}
		s += fmt.Sprintf("%02X", c)
	}

	return s
}

// intToHex convert a bigint to its hexadecimal string representation
func intToHex(i *big.Int) string {
	hex := fmt.Sprintf("%X", i)
	if len(hex)%2 == 1 {
		// Add an initial 0 if odd number of chars
		hex = "0" + hex
	}

	// Insert a column between any 2 chars
	var r bytes.Buffer
	last := len(hex) - 1
	for i, c := range hex {
		r.WriteString(string(c))
		if i%2 == 1 && i != last {
			r.WriteString(":")
		}
	}
	return r.String()
}

// encodePem encode a given X509 certificate to a PEM format
func encodePem(cert *x509.Certificate) string {
	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}
	b := pem.EncodeToMemory(block)
	return string(b)
}

// parseCertificate parses a x509 certificate.
// Modified from https://github.com/cloudflare/cfssl/blob/master/certinfo/certinfo.go
func parseCertificate(cert *x509.Certificate, total, index int) *Certificate {
	sha1Fingerprint := sha1.Sum(cert.Raw)
	sha256Fingerprint := sha256.Sum256(cert.Raw)
	c := &Certificate{
		CertificateNumber: fmt.Sprintf("%d/%d", index+1, total),
		SerialNumber:      cert.SerialNumber.String(),
		SerialNumberHex:   intToHex(cert.SerialNumber),

		Subject:            parseName(cert.Subject),
		SubjectKeyId:       bytesToHex(cert.SubjectKeyId),
		DNSNames:           cert.DNSNames,
		Issuer:             parseName(cert.Issuer),
		NotBefore:          parseTime(cert.NotBefore),
		NotAfter:           parseTime(cert.NotAfter),
		SHA1Fingerprint:    bytesToHex(sha1Fingerprint[:]),
		SHA256Fingerprint:  bytesToHex(sha256Fingerprint[:]),
		OCSPServer:         strings.Join(cert.OCSPServer, ", "),
		Signature:          bytesToHex(cert.Signature),
		SignatureAlgorithm: fmt.Sprintf("%s", cert.SignatureAlgorithm),
		CertPublicKey:      parsePublicKey(cert.PublicKey, cert.PublicKeyAlgorithm),
		AuthorityKeyId:     bytesToHex(cert.AuthorityKeyId),
		KeyUsage:           strings.Join(getKeyUsage(cert.KeyUsage), ", "),
		Ca:                 cert.IsCA,
		RawPEM:             encodePem(cert),
	}
	for _, ip := range cert.IPAddresses {
		c.IPAddresses = append(c.IPAddresses, ip.String())
	}
	return c
}

// parseName parses a new name from a *pkix.Name
// Modified from https://github.com/cloudflare/cfssl/blob/master/certinfo/certinfo.go
func parseName(name pkix.Name) Name {
	n := Name{
		CommonName:         name.CommonName,
		SerialNumber:       name.SerialNumber,
		Country:            strings.Join(name.Country, ","),
		Organization:       strings.Join(name.Organization, ","),
		OrganizationalUnit: strings.Join(name.OrganizationalUnit, ","),
		Locality:           strings.Join(name.Locality, ","),
		Province:           strings.Join(name.Province, ","),
		StreetAddress:      strings.Join(name.StreetAddress, ","),
		PostalCode:         strings.Join(name.PostalCode, ","),
	}

	for i := range name.Names {
		n.Names = append(n.Names, name.Names[i].Value)
	}

	for i := range name.ExtraNames {
		n.ExtraNames = append(n.ExtraNames, name.ExtraNames[i].Value)
	}

	return n
}

// parseChains parses a list of chains
func parseChains(chains [][]*x509.Certificate) *Chains {
	total := len(chains)
	cs := &Chains{}

	for i, certs := range chains {
		cs.CertificateChains = append(cs.CertificateChains, *parseCertificates(certs, total, i))
	}
	return cs
}

// parseCertificates parses a list of certificates
func parseCertificates(chain []*x509.Certificate, totalChains, index int) *CertificateChain {
	cc := &CertificateChain{
		ChainNumber: fmt.Sprintf("%d/%d", index+1, totalChains),
	}
	totalCerts := len(chain)
	for i, cert := range chain {
		cc.Certificates = append(cc.Certificates, *parseCertificate(cert, totalCerts, i))
	}
	return cc
}

// GenJsonChains generate a JSON string for a list of chains
func GenJsonChains(chains [][]*x509.Certificate) (string, error) {
	cs := parseChains(chains)

	var err error
	var buf []byte
	if cs != nil {
		buf, err = json.MarshalIndent(cs, "", "  ")
		if err != nil {
			return "", err
		}
	}
	return string(buf), nil
}

// GenJson generate a JSON string for a single certificate
func GenJson(cert *x509.Certificate) (string, error) {
	c := parseCertificate(cert, 1, 0)

	var err error
	var buf []byte
	if c != nil {
		buf, err = json.MarshalIndent(c, "", "  ")
		if err != nil {
			return "", err
		}
	}
	return string(buf), nil
}
