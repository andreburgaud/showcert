# ShowCert

`showcert` displays SSL certificate attributes in JSON format.

The target can be a local file or a remote server. The argument is a server name and port (if different than the default TLS port 443).

## Examples

The simplest example would be something like:

```
showcert google.com
```

For more details about the options available with `showcert`, execute `showcert` with the `--help` option:

```
showcert --help
```

```
showcert shows details about local or remote SSL certificates

USAGE:
  showcert [FLAGS] <domain_name> | <cert_file>

FLAGS:
  -h, --help                  Displays this help
  -V, --version               Displays application version
  -f, --file <cert_file>      Parses a local certificate file (PEM format)
  -v, --verify                Requires certificate chain verification
  --host <host:[port]>        Parses a remote certificate for a given host
  --cafile <PEM_file>         Loads CAs from a PEM file
  --cadir <directory>         Loads CAs from a directory containing PEM files

EXAMPLES:
  showcert google.com
  showcert --host google.com
  showcert --host google.com:443
  showcert --verify google.com
  showcert --verify --domain google.com
  showcert --file some_cert.pem
  showcert --cafile some_ca.pem
  showcert --cadir some_directory
```

For a better user experience, you can pipe the `showcert` JSON output to [jq](https://stedolan.github.io/jq/).

```
showcert --verify google.com | jq
```
```json
{
  "tls_version": "1.3",
  "cipher_suite": "TLS_AES_128_GCM_SHA256",
  "host_verification": true,
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
            "*.datacompute.google.com"
          ]
        }
      ]
    }
  ]
}
```

_The JSON above is truncated to improve the readability of this document._

To extract a specific attribute of the JSON file, you can use `jq`. Here are some examples
(stderr output omitted for improved readability):

Extract the first raw PEM certificate:

```
showcert google.com | jq -r '.chains[0].certificates[0].pem'
```
```
-----BEGIN CERTIFICATE-----
MIIN7jCCDNagAwIBAgIRAKz/vGtNq+cyCkMq+UTzB2MwDQYJKoZIhvcNAQELBQAw
RjELMAkGA1UEBhMCVVMxIjAgBgNVBAoTGUdvb2dsZSBUcnVzdCBTZXJ2aWNlcyBM
...
```

List all the SHA256 fingerprints:

```
showcert --verify google.com | jq '.chains[].certificates[].sha256_fingerprint'
```
```
"6D:8C:E1:6A:5C:A3:F0:91:40:DE:07:37:AD:4A:AD:DA:66:6A:AF:14:16:AB:9F:4E:7E:E8:40:8B:E9:1B:7B:F3"
"23:EC:B0:3E:EC:17:33:8C:4E:33:A6:B4:8A:41:DC:3C:DA:12:28:1B:BC:3F:F8:13:C0:58:9D:6C:C2:38:75:22"
"2A:57:54:71:E3:13:40:BC:21:58:1C:BD:2C:F1:3E:15:84:63:20:3E:CE:94:BC:F9:D3:CC:19:6B:F0:9A:54:72"
"6D:8C:E1:6A:5C:A3:F0:91:40:DE:07:37:AD:4A:AD:DA:66:6A:AF:14:16:AB:9F:4E:7E:E8:40:8B:E9:1B:7B:F3"
"23:EC:B0:3E:EC:17:33:8C:4E:33:A6:B4:8A:41:DC:3C:DA:12:28:1B:BC:3F:F8:13:C0:58:9D:6C:C2:38:75:22"
"3E:E0:27:8D:F7:1F:A3:C1:25:C4:CD:48:7F:01:D7:74:69:4E:6F:C5:7E:0C:D9:4C:24:EF:D7:69:13:39:18:E5"
"EB:D4:10:40:E4:BB:3E:C7:42:C9:E3:81:D3:1E:F2:A4:1A:48:B6:68:5C:96:E7:CE:F3:C1:DF:6C:D4:33:1C:99"
```

Display all authority key ids for CA certificates:

```
showcert --verify google.com | jq '.chains[].certificates[] | select(.certificate_authority == true) | .authority_key_id'
```
```
"E4:AF:2B:26:71:1A:2B:48:27:85:2F:52:66:2C:EF:F0:89:13:71:3E"
null
"E4:AF:2B:26:71:1A:2B:48:27:85:2F:52:66:2C:EF:F0:89:13:71:3E"
"60:7B:66:1A:45:0D:97:CA:89:50:2F:7D:04:CD:34:A8:FF:FC:FD:4B"
null
```

## Docker

A docker image is available at https://hub.docker.com/r/andreburgaud/showcert.

To use the image and fetch the Google certificates:

```
docker run --rm andreburgaud/showcert google.com
...
```

You can also pipe the result to [jq](https://stedolan.github.io/jq/):

```
docker run --rm andreburgaud/showcert google.com | jq
...
```

or to extract only the first certificate in PEM format:

```
docker run --rm andreburgaud/showcert google.com | jq -r '.chains[0].certificates[0].pem'
...
```

## Build

### Development

If you have [just](https://github.com/casey/just) and [Go](https://go.dev/) installed:
```
just build
```

If you only have [Go](https://go.dev/) installed:

```
go build -o showcert showcert/cmd/showcert
```

### Release

`Showcert` uses [GoReleaser](https://goreleaser.com/) to cross-compile the project and deploy binaries to GitHub.

To generate a local release, you can execute the following command:

```
just local-release
```

If you only have [Go](https://go.dev/) installed:

```
go build -o showcert -ldflags="-s -w -X 'showcert/internal/cli.Version=1.2.3'" showcert/cmd/showcert
```

## License

The `showcert` source code is released under the [MIT license](LICENSE).

`showcert` includes some code from [CFSSL](https://github.com/cloudflare/cfssl) released under a BSD-2-Clause license. References to `CFSSL` are included in the appropriate `showcert` files.
