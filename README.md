# XML Digital Signature client

This is a bare-bones command-line tool for signing XML according to the
[XML Digital Signature standard](https://www.w3.org/TR/xmldsig-core1/) and sending it, via HTTP POST request, to a
server.

## Usage

Execute `xmldsig-client` and provide the XML to sign via Standard Input, e.g.

```shell
$ xmldsig-client --schema my_schema.xsd --cert cert.pem --key private.pem --url http://localhost/test < my_data.xml
```

The `xmldsig-client` tool requires `--cert` and `--key` arguments, which should be the certificate and private key in
PEM format. It also accepts:
- `--schema`: Validate the provided XML against this schema
- `--url`: POST the signed XML to this URL
