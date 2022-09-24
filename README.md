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

For a better user experience, you can pipe the `showcert` JSON output to [jq](https://stedolan.github.io/jq/).

```
[andre@saturne showcert]$ ./showcert --verified-chains google.com | jq
Hostname google.com verification successful
TLS Version  : 1.3
Cipher Suite : TLS_AES_128_GCM_SHA256
Server Name  : google.com
```
```json
{
  "chains": [
    {
      "chain_number": "1/2",
      "certificates": [
        {
          "certificate_number": "1/3",
          "serial_number": "229955072568388950586185815992730584931",
          "serial_number_hex": "AC:FF:BC:6B:4D:AB:E7:32:0A:43:2A:F9:44:F3:07:63",
          "subject": {
            "common_name": "*.google.com",
            "names": [
              "*.google.com"
            ]
          },
          "dns_names": [
            "*.google.com",
            "*.appengine.google.com",
            "*.bdn.dev",
            "*.origin-test.bdn.dev",
            "*.cloud.google.com",
            "*.crowdsource.google.com",
            "*.datacompute.google.com",
...
```


## Build

## Development

```
$ just build
```

## Release

```
$ just release
```
