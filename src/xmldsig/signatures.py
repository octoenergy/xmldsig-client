import base64

import signxml
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from lxml import etree
from OpenSSL import crypto

XML_NAMESPACES = {
    "ds": "http://www.w3.org/2000/09/xmldsig#",
    "dsig11": "http://www.w3.org/2009/xmldsig11#",
}
"""
XML namespaces used by signatures.
"""


class XMLError(ValueError):
    """
    Some signed XML is malformed or invalid in some way.
    """

    pass


class SignatureError(ValueError):
    """
    An XML signature is invalid or malformed.
    """

    pass


class CertificateNotFoundError(ValueError):
    def __init__(self, issuer: x509.Name, serial_number: int):
        super().__init__("Certificate not found")
        self.issuer = issuer
        self.serial_number = serial_number


class XMLSigner:
    """
    Signs XML messages using a private key, according to https://www.w3.org/TR/xmldsig-core1/.
    """

    SIGNATURE_ALGORITHM_ID = "ecdsa-sha256"
    """
    Algorithm used to generate request signatures.
    """

    DIGEST_ALGORITHM_ID = "sha256"
    """
    Algorithm used to hash request XML before signing.
    """

    CANONICALIZATION_ALGORITHM_ID = "http://www.w3.org/2001/10/xml-exc-c14n#"
    """
    Algorithm used to transform request XML into a canonical form before hashing.
    """

    include_issuer_serial: bool = True
    include_x509_digest: bool = True

    def __init__(self, key: ec.EllipticCurvePrivateKey, cert: crypto.X509):
        """
        :param key: The private key to use for generating signatures.
        :param cert: The certificate that contains the corresponding public key, used for verification.
        """
        self.signer = signxml.XMLSigner(
            method=signxml.methods.enveloped,
            signature_algorithm=self.SIGNATURE_ALGORITHM_ID,
            digest_algorithm=self.DIGEST_ALGORITHM_ID,
            c14n_algorithm=self.CANONICALIZATION_ALGORITHM_ID,
        )
        if not key:
            raise ValueError("Must provide private key for generating signatures")
        self.key = key
        if not cert:
            raise ValueError(
                "Must provide certificate used to verify generated signatures"
            )
        self.cert = cert

    def sign(self, xml: bytes) -> bytes:
        """
        Adds a Signature element to some XML.
        :param xml: The XML to sign.
        :return: The XML with an added Signature element.
        :raise XMLError: if XML is invalid
        :raise SignatureError: if signature is invalid
        """
        try:
            parsed_xml = etree.fromstring(xml)
        except ValueError as e:
            raise XMLError() from e

        signed_xml: etree.ElementBase = self.signer.sign(
            data=parsed_xml, key=self.key, cert=[self.cert]
        )
        # TODO(RJPercival): Add support for X509IssuerSerial to signxml library.
        if self.include_issuer_serial:
            try:
                self._add_issuer_serial(signed_xml=signed_xml)
            except XMLError as e:
                raise SignatureError(
                    "Generated signature did not have expected format"
                ) from e

        if self.include_x509_digest:
            try:
                self._add_digest(signed_xml)
            except XMLError as e:
                raise SignatureError(
                    "Generated signature did not have expected format"
                ) from e

        return etree.tostring(signed_xml, encoding="utf-8")

    def _add_issuer_serial(self, signed_xml: etree.ElementBase) -> None:
        """
        Add X509IssuerSerial element to request signature.
        Note that this element is deprecated; prefer X509Digest when possible.
        """
        x509_data = _get_element(signed_xml, "./ds:Signature/ds:KeyInfo/ds:X509Data")

        if x509_data.xpath("./ds:X509IssuerSerial", namespaces=XML_NAMESPACES):
            # Already has an X509IssuerSerial element - nothing to do.
            return

        issuer_serial: etree.ElementBase = etree.SubElement(
            x509_data, "{%s}X509IssuerSerial" % XML_NAMESPACES["ds"]
        )

        issuer_name: etree.ElementBase = etree.SubElement(
            issuer_serial, "{%s}X509IssuerName" % XML_NAMESPACES["ds"]
        )
        issuer_name.text = b",".join(
            b"%s=%s" % (key, value)
            for key, value in reversed(self.cert.get_issuer().get_components())
        ).decode("utf-8")

        serial_number: etree.ElementBase = etree.SubElement(
            issuer_serial, "{%s}X509SerialNumber" % XML_NAMESPACES["ds"]
        )
        serial_number.text = str(self.cert.get_serial_number())

    def _add_digest(self, signed_xml: etree.ElementBase) -> None:
        """
        Add X509Digest element to the request signature.
        """
        x509_data = _get_element(signed_xml, "./ds:Signature/ds:KeyInfo/ds:X509Data")
        if x509_data.xpath("./dsig11:X509Digest", namespaces=XML_NAMESPACES):
            # Already has an X509Digest element - nothing to do.
            return

        digest: etree.ElementBase = etree.SubElement(
            x509_data, "{%s}X509Digest" % XML_NAMESPACES["dsig11"]
        )

        digest.set("Algorithm", "http://www.w3.org/2001/04/xmlenc#sha256")
        digest.text = base64.b64encode(
            self.cert.to_cryptography().fingerprint(hashes.SHA256())
        )


def _get_element(root_element: etree.ElementTree, xpath: str) -> etree.Element:
    elements = root_element.xpath(xpath, namespaces=XML_NAMESPACES)
    if (count := len(elements)) != 1:
        raise XMLError(f"Expected 1 element matching '{xpath}', found {count}")
    return elements[0]
