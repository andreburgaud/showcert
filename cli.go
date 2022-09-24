package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

const (
	version = "0.1.0"
)

type Command struct {
	help           bool
	ver            bool
	verifiedChains bool
	cert           string
	domain         string
	args           []string
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
	fmt.Printf("  %s --verified-chains       Request certificate chain verification\n", exe)
	fmt.Printf("  %s --domain <domain_name>  Point to a remote certificate\n", exe)
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Printf("  %s --domain google.com\n", exe)
	fmt.Printf("  %s google.com\n", exe)
	fmt.Printf("  %s --verified-chains --domain google.com \n", exe)
	fmt.Printf("  %s --verified-chains google.com\n", exe)
	fmt.Printf("  %s --cert some_cert.pem\n", exe)
}

// parseOptions parse CLI options and return a populated Command
func parseOptions() *Command {

	// Overwrite the default help to show the overall tool usage rather than the usage for the top flags
	// To test it, execute the app with a non-valid option
	flag.Usage = func() {
		usage()
	}

	var cmd = Command{
		help:           false,
		ver:            false,
		verifiedChains: false,
	}

	flag.BoolVar(&cmd.help, "help", false, fmt.Sprintf("Display %s usage", getExe()))
	flag.BoolVar(&cmd.ver, "version", false, fmt.Sprintf("Display %s version", getExe()))
	flag.BoolVar(&cmd.verifiedChains, "verified-chains", false, "Parse the certs of the verified chains (only with --domain options)")
	flag.StringVar(&cmd.cert, "cert", "", "certificate file")
	flag.StringVar(&cmd.domain, "domain", "", "domain name and port (example: google.com:443)")

	flag.Parse()

	if cmd.help {
		usage()
		os.Exit(0)
	}

	if cmd.ver {
		fmt.Printf("%s version %s\n", getExe(), version)
		os.Exit(0)
	}

	cmd.args = flag.Args()

	return &cmd
}

// execute the command from the properties of Command
func (cmd Command) execute() error {

	if len(cmd.cert) > 0 {
		err := showLocalCert(cmd.cert)
		if err != nil {
			return err
		}
		return nil
	}

	if len(cmd.domain) > 0 {
		err := showRemoteCerts(cmd.domain, cmd.verifiedChains)
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
		err := showRemoteCerts(arg, cmd.verifiedChains)
		if err != nil {
			return err
		}
		return nil
	}

	_, _ = fmt.Fprintln(os.Stderr, "no option or argument provided")
	usage()
	return nil
}

// showLocalCert trigger the command to open a local cert file and show the details about it
func showLocalCert(certFile string) error {
	cert, err := getLocalCert(certFile)
	if err != nil {
		return err
	}
	jsonCert, err := genJson(cert)
	if err != nil {
		return err
	}
	fmt.Println(jsonCert)
	return nil
}

// showRemoteCert trigger the command to open a local cert file and show the details about it
func showRemoteCerts(domain string, verif bool) error {
	chains, err := getRemoteCerts(domain, verif)
	if err != nil {
		return err
	}

	jsonChains, err := genJsonChains(chains)
	if err != nil {
		return err
	}
	fmt.Println(jsonChains)
	return nil
}
