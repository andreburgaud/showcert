# ShowCert

`showcert` exports the elements of an SSL certificate into a JSON format. 
The target can be a local file or a remote server. In the latter scenario, 
the target is a domain.

## Examples

```
$ ./showcert --help

showcert shows details about local or remote SSL certificates

Usage:
  showcert --help                  Display this help
  showcert --version               Display application version
  showcert --cert <cert_file>      Point to a local certificate file
  showcert --verified-chains       Request certificate chain verification
  showcert --domain <domain_name>  Point to a remote certificate

Examples:
  showcert --domain google.com
  showcert google.com
  showcert --verified-chains --domain google.com 
  showcert --verified-chains google.com
  showcert --cert some_cert.pem
```

For a better user experience, you can pipe the JSON output of `showcert` to [jq](https://stedolan.github.io/jq/).

# Development

## Build

```
$ just build
```


