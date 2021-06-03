import argparse
import sys
from typing import BinaryIO

import requests
import xmlschema
from cryptography.hazmat import backends as crypto_backends
from cryptography.hazmat.primitives import serialization
from OpenSSL import crypto

from . import signatures

arg_parser = argparse.ArgumentParser(prog="xmldsig-client", description="Send a signed XML message")
arg_parser.add_argument(
    "--key",
    type=argparse.FileType("rb"),
    required=True,
    help="Private key that should be used to sign the message (in PEM format)",
)
arg_parser.add_argument(
    "--cert",
    type=argparse.FileType("rb"),
    required=True,
    help="Certificate that can be used to verify the signature on the message (in PEM format)",
)
arg_parser.add_argument(
    "--schema",
    type=argparse.FileType("r"),
    required=False,
    help="XML schema (XSD) to use to verify the message format before sending it",
)
arg_parser.add_argument(
    "--url",
    type=str,
    required=False,
    help="URL to which the message will be sent. If omitted, the message will be printed to stdout.",
)


def load_private_key(file: BinaryIO):
    return serialization.load_pem_private_key(
        data=file.read(), password=None, backend=crypto_backends.default_backend()
    )


def load_cert(file: BinaryIO):
    return crypto.load_certificate(type=crypto.FILETYPE_PEM, buffer=file.read())


def main():
    # Command-line arguments
    args = arg_parser.parse_args()

    # Read XML from stdin and validate
    xml = sys.stdin.read()
    if not xml:
        sys.exit("Please write the XML message to send")

    if args.schema:
        print("Validating input against schema...")
        schema = xmlschema.XMLSchema(args.schema)
        try:
            schema.validate(xml)
        except xmlschema.XMLSchemaValidationError as e:
            sys.exit(str(e))

    print("Generating XML signature...")
    signer = signatures.XMLSigner(
        key=load_private_key(args.key), cert=load_cert(args.cert)
    )
    signed_xml = signer.sign(xml.encode("utf-8"))

    if args.url:
        print(f"Sending to {args.url}...")

        try:
            response = requests.post(
                url=args.url,
                data=signed_xml,
                allow_redirects=True,
            )
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            sys.exit(str(e))

        print(f"Request sent to {args.url} successfully")
    else:
        print(signed_xml.decode("utf-8"))


if __name__ == "__main__":
    main()
