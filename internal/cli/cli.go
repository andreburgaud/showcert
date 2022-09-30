package cli

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"showcert/internal/cert"
	"showcert/internal/client"
)

var (
	Version = "dev"
)

// Command holds the options and argument of the CLI
type Command struct {
	help    bool
	version bool
	verify  bool
	cert    string
	domain  string
	args    []string
}

// ShowCert is the top level container used to generate the global JSON
type ShowCert struct {
	ShowCertVersion   string                  `json:"showcert_version"`
	TlsVersion        string                  `json:"tls_version,omitempty"`
	CipherSuite       string                  `json:"cipher_suite,omitempty"`
	HostVerification  bool                    `json:"host_verification"`
	CertificateChains []cert.CertificateChain `json:"chains"`
}

// getExe return the executable name without any path
func getExe() string {
	path, _ := os.Executable()
	exe := filepath.Base(path)
	return exe
}

// isFile helper to determine if a given filename is an existing file on the file system
func isFile(f string) bool {
	if _, err := os.Stat(f); errors.Is(err, os.ErrNotExist) {
		return false
	}
	return true
}

// usage displays the usage of the command with all its sub commands
func usage() {
	exe := getExe()
	fmt.Printf("\n%s shows details about local or remote SSL certificates\n\n", getExe())
	fmt.Println("Usage:")
	fmt.Printf("  %s --help                  Display this help\n", exe)
	fmt.Printf("  %s --version               Display application version\n", exe)
	fmt.Printf("  %s --cert <cert_file>      Point to a local certificate file\n", exe)
	fmt.Printf("  %s --verify <domain_name>  Request certificate chain verification\n", exe)
	fmt.Printf("  %s --domain <domain_name>  Point to a remote certificate\n", exe)
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Printf("  %s --domain google.com\n", exe)
	fmt.Printf("  %s --domain google.com:443\n", exe)
	fmt.Printf("  %s google.com\n", exe)
	fmt.Printf("  %s --verify --domain google.com \n", exe)
	fmt.Printf("  %s --verify google.com\n", exe)
	fmt.Printf("  %s --cert some_cert.pem\n", exe)
}

// ParseOptions parse CLI options and return a populated Command
func ParseOptions() *Command {

	// Overwrite the default help to show the overall tool usage rather than the usage for the top flags
	// To test it, execute the app with a non-valid option
	flag.Usage = func() {
		usage()
	}

	var cmd = Command{
		help:    false,
		verify:  false,
		version: false,
	}

	flag.BoolVar(&cmd.help, "help", false, fmt.Sprintf("Display %s usage", getExe()))
	flag.BoolVar(&cmd.version, "version", false, fmt.Sprintf("Display %s version", getExe()))
	flag.BoolVar(&cmd.verify, "verify", false, "Parse the certs of the verified chains (only with --domain options)")
	flag.StringVar(&cmd.cert, "cert", "", "certificate file")
	flag.StringVar(&cmd.domain, "domain", "", "domain name and port (example: google.com:443)")

	flag.Parse()

	if cmd.help {
		usage()
		os.Exit(0)
	}

	if cmd.version {
		fmt.Printf("%s version %s\n", getExe(), Version)
		os.Exit(0)
	}

	cmd.args = flag.Args()

	return &cmd
}

// Execute the command from the properties of Command
func (cmd Command) Execute() error {

	if len(cmd.cert) > 0 {
		err := showLocalCert(cmd.cert)
		if err != nil {
			return err
		}
		return nil
	}

	if len(cmd.domain) > 0 {
		err := showRemoteCerts(cmd.domain, cmd.verify)
		if err != nil {
			return err
		}
		return nil
	}

	// Check if any argument is a domain or a cert file and run the equivalent of --domain or --cert
	if len(cmd.args) > 0 {
		arg := cmd.args[0]
		if isFile(arg) {
			err := showLocalCert(arg)
			if err != nil {
				return err
			}
			return nil
		}
		// Assuming this is a domain
		err := showRemoteCerts(arg, cmd.verify)
		if err != nil {
			return err
		}
		return nil
	}

	_, _ = fmt.Fprintln(os.Stderr, "no option or argument provided")
	usage()
	return nil
}

// buildJsonCert generate a JSON string for a single certificate
func buildJsonCert(x509Cert *x509.Certificate) (string, error) {
	c := cert.ParseCertificate(x509Cert, 1, 0)
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

// showLocalCert trigger the command to open a local cert file and show the details about it
func showLocalCert(certFile string) error {
	c, err := client.GetLocalCert(certFile)
	if err != nil {
		return err
	}
	jsonCert, err := buildJsonCert(c)
	if err != nil {
		return err
	}
	fmt.Println(jsonCert)
	return nil
}

// buildJsonChains creates a JSON string from a Chains structure
func buildJsonChains(showCert *ShowCert) (string, error) {
	buf, err := json.MarshalIndent(showCert, "", "  ")
	if err != nil {
		return "", err
	}
	return string(buf), nil
}

// showRemoteCert trigger the command to open a local cert file and show the details about it
func showRemoteCerts(domain string, verify bool) error {
	//c := client.Connect(domain, verify)
	response, err := client.GetRemoteCerts(domain, verify)
	if err != nil {
		return err
	}

	sc := ShowCert{
		ShowCertVersion:   Version,
		TlsVersion:        response.TlsVersion,
		CipherSuite:       response.CipherSuite,
		HostVerification:  response.HostVerification,
		CertificateChains: cert.ParseChains(response.CertificateChains),
	}

	j, err := buildJsonChains(&sc)
	if err != nil {
		return err
	}
	fmt.Println(j)
	return nil
}
