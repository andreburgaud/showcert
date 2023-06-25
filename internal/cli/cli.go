package cli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"showcert/internal/client"

	"showcert/internal/cert"
)

var (
	Version = "dev"
)

// Command holds the options and argument of the CLI
type Command struct {
	help    bool
	version bool
	verify  bool
	cafile  string
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

const options = `
  -h, --help                  Displays this help
  -V, --version               Displays application version
  -c, --cert <cert_file>      Parses a local certificate file
  -d, --domain <domain_name>  Parses a remote certificate
  -v, --verify                Requires certificate chain verification

`

const usage = `
  %s [FLAGS] <domain_name> | <cert_file>

`

const examples = `
  %[1]s google.com
  %[1]s --domain google.com
  %[1]s --domain google.com:443
  %[1]s --verify google.com
  %[1]s --verify --domain google.com
  %[1]s --cert some_cert.pem

`

// Usage displays the usage of the command with all its sub commands
func Usage() {
	exe := getExe()
	fmt.Printf("\n%s shows details about local or remote SSL certificates\n\n", getExe())
	fmt.Print("USAGE:")
	fmt.Printf(usage, exe)
	fmt.Print("FLAGS:")
	fmt.Print(options)
	fmt.Print("EXAMPLES:")
	fmt.Printf(examples, exe)
}

// ParseOptions parse CLI options and return a populated Command
func ParseOptions() *Command {

	// Overwrite the default help to show the overall tool usage rather than the usage for the top flags
	// To test it, execute the app with a non-valid option
	flag.Usage = func() {
		Usage()
	}

	var cmd = Command{
		help:    false,
		verify:  false,
		version: false,
	}

	flag.BoolVar(&cmd.help, "help", false, "help")
	flag.BoolVar(&cmd.help, "h", false, "help")
	flag.BoolVar(&cmd.version, "version", false, "version")
	flag.BoolVar(&cmd.version, "V", false, "version")
	flag.BoolVar(&cmd.verify, "verify", false, "verify")
	flag.BoolVar(&cmd.verify, "v", false, "verify")
	flag.StringVar(&cmd.cert, "cert", "", "certificate")
	flag.StringVar(&cmd.cert, "c", "", "certificate")
	flag.StringVar(&cmd.cafile, "cafile", "", "cafile")
	flag.StringVar(&cmd.domain, "domain", "", "domain")
	flag.StringVar(&cmd.domain, "d", "", "domain")
	flag.Parse()

	if cmd.help {
		Usage()
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
		err := showRemoteCerts(cmd.domain, cmd.verify, cmd.cafile)
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
		err := showRemoteCerts(arg, cmd.verify, cmd.cafile)
		if err != nil {
			return err
		}
		return nil
	}

	_, _ = fmt.Fprintln(os.Stderr, "no option or argument provided")
	Usage()
	return nil
}

// showLocalCert trigger the command to open a local cert file and show the details about it
func showLocalCert(certFile string) error {
	certs, err := client.GetLocalCerts(certFile)
	if err != nil {
		return err
	}
	chain := cert.ParseCertificates(certs, 1, 0)

	j, err := buildJsonChain(chain)
	if err != nil {
		return err
	}
	fmt.Println(j)
	return nil
}

// buildJsonChain creates a JSON string from one chain of certificates (one or more certificates)
func buildJsonChain(chain *cert.CertificateChain) (string, error) {
	buf, err := json.MarshalIndent(chain, "", "  ")
	if err != nil {
		return "", err
	}
	return string(buf), nil
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
func showRemoteCerts(domain string, verify bool, cafile string) error {
	response, err := client.GetRemoteCerts(domain, verify, cafile)
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
