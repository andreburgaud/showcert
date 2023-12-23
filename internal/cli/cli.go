package cli

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"showcert/internal/cert"
	"showcert/internal/client"
)

var (
	Version = "dev"
)

const ShowCertUrl = "https://github.com/andreburgaud/showcert"

// Command holds the options and argument of the CLI
type Command struct {
	help    bool
	version bool
	verify  bool
	cafile  string
	cadir   string
	file    string
	host    string
	port    string
}

// ShowCert is the header
type ShowCert struct {
	Version          string `json:"version"`
	Url              string `json:"url"`
	TlsVersion       string `json:"tls_version,omitempty"`
	Host             string `json:"host,omitempty"`
	Port             string `json:"port,omitempty"`
	File             string `json:"file,omitempty"`
	CipherSuite      string `json:"cipher_suite,omitempty"`
	HostVerification bool   `json:"host_verification"`
	CaFile           string `json:"cafile,omitempty"`
	CaDir            string `json:"cadir,omitempty"`
}

// ShowCertSuccess is the top level container used to generate the global JSON
type ShowCertSuccess struct {
	ShowCert          ShowCert                `json:"showcert"`
	TlsVersion        string                  `json:"tls_version"`
	CipherSuite       string                  `json:"cipher_suite"`
	CertificateChains []cert.CertificateChain `json:"chains"`
}

// ShowCertError is the container for an error
type ShowCertError struct {
	ShowCert     ShowCert `json:"showcert"`
	ErrorMessage string   `json:"error"`
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
  -f, --file <cert_file>      Parses a local certificate file (PEM format)
  -v, --verify                Requires certificate chain verification
  --host <host:[port]>        Parses a remote certificate for a given host
  --cafile <PEM_file>         Loads CAs from a PEM file
  --cadir <directory>         Loads CAs from a directory containing PEM files

`

const usage = `
  %s [FLAGS] <domain_name> | <cert_file>

`

const examples = `
  %[1]s google.com
  %[1]s --host google.com
  %[1]s --host google.com:443
  %[1]s --verify google.com
  %[1]s --verify --domain google.com
  %[1]s --file some_cert.pem
  %[1]s --cafile some_ca.pem
  %[1]s --cadir some_directory

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
	flag.StringVar(&cmd.file, "file", "", "file")
	flag.StringVar(&cmd.file, "f", "", "file")
	flag.StringVar(&cmd.cafile, "cafile", "", "cafile")
	flag.StringVar(&cmd.cadir, "cadir", "", "cadir")
	flag.StringVar(&cmd.host, "host", "", "host")
	flag.Parse()

	if cmd.help {
		Usage()
		os.Exit(0)
	}

	if cmd.version {
		fmt.Printf("%s version %s\n", getExe(), Version)
		os.Exit(0)
	}

	args := flag.Args()

	// Check if any argument is a domain or a cert file and run the equivalent of --domain or --cert
	if len(args) > 0 {
		arg := args[0]
		if isFile(arg) {
			cmd.file = arg
		}
		// Assuming this is a domain
		cmd.host = arg
	}

	h, p, err := net.SplitHostPort(cmd.host)
	if err != nil {
		cmd.port = "443"
	} else {
		cmd.host = h
		cmd.port = p
	}
	return &cmd
}

// Execute the command from the properties of Command
func (cmd Command) Execute() error {

	// Read local PEM file
	if len(cmd.file) > 0 {
		err := showLocalCert(cmd.file)
		if err != nil {
			return err
		}
		return nil
	}

	// Retreive a remote cert
	if len(cmd.host) > 0 {
		err := showRemoteCerts(cmd.verify, cmd.host, cmd.port, cmd.cafile, cmd.cadir)
		if err != nil {
			return err
		}
		return nil
	}

	// read PEM from stdin
	err := showStdinCert()
	if err != nil {
		return err
	}

	return nil
}

// PrintError prints an error in JSON format
func (cmd Command) PrintError(err error) {
	sce := ShowCertError{
		ShowCert: ShowCert{
			Version:          Version,
			Url:              ShowCertUrl,
			HostVerification: cmd.verify,
			Host:             cmd.host,
			Port:             cmd.port,
			File:             cmd.file,
			CaFile:           cmd.cafile,
			CaDir:            cmd.cadir,
		},
		ErrorMessage: err.Error(),
	}
	buf, err := json.MarshalIndent(sce, "", "  ")
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(string(buf))
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

// showStdinCert trigger the command to parse stdin (assuming a PEM format) and printing human readable certs
func showStdinCert() error {
	var data []string
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		data = append(data, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	certs, err := client.GetCertsFromBytes([]byte(strings.Join(data, "\n")))
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
func buildJsonChains(showCertSuccess *ShowCertSuccess) (string, error) {
	buf, err := json.MarshalIndent(showCertSuccess, "", "  ")
	if err != nil {
		return "", err
	}
	return string(buf), nil
}

// showRemoteCert trigger the command to open a local cert file and show the details about it
func showRemoteCerts(verify bool, host, port, cafile, cadir string) error {
	response, err := client.GetRemoteCerts(verify, host, port, cafile, cadir)
	if err != nil {
		return err
	}

	sc := ShowCertSuccess{
		ShowCert: ShowCert{
			Version:          Version,
			Url:              ShowCertUrl,
			HostVerification: verify,
			Host:             host,
			Port:             port,
			CaFile:           cafile,
			CaDir:            cadir,
		},
		TlsVersion:        response.TlsVersion,
		CipherSuite:       response.CipherSuite,
		CertificateChains: cert.ParseChains(response.CertificateChains),
	}

	j, err := buildJsonChains(&sc)
	if err != nil {
		return err
	}
	fmt.Println(j)
	return nil
}
