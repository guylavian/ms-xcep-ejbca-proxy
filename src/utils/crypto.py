"""
Cryptographic utilities for certificate operations.

Handles CSR parsing, certificate manipulation, and PKCS#7 creation.
"""

import base64
import logging
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.serialization import pkcs7, Encoding
from cryptography.x509.oid import NameOID, ExtensionOID

logger = logging.getLogger(__name__)


class CryptoError(Exception):
    """Cryptographic operation error."""
    pass


def parse_csr(csr_data: bytes) -> x509.CertificateSigningRequest:
    """
    Parse a PKCS#10 Certificate Signing Request.

    Args:
        csr_data: CSR in DER or PEM format

    Returns:
        Parsed CSR object

    Raises:
        CryptoError: If CSR is invalid
    """
    try:
        # Try DER first
        return x509.load_der_x509_csr(csr_data)
    except Exception:
        pass

    try:
        # Try PEM
        return x509.load_pem_x509_csr(csr_data)
    except Exception:
        pass

    raise CryptoError("Invalid CSR format - not DER or PEM")


def parse_certificate(cert_data: bytes) -> x509.Certificate:
    """
    Parse an X.509 certificate.

    Args:
        cert_data: Certificate in DER or PEM format

    Returns:
        Parsed certificate object

    Raises:
        CryptoError: If certificate is invalid
    """
    try:
        return x509.load_der_x509_certificate(cert_data)
    except Exception:
        pass

    try:
        return x509.load_pem_x509_certificate(cert_data)
    except Exception:
        pass

    raise CryptoError("Invalid certificate format - not DER or PEM")


def get_csr_subject(csr: x509.CertificateSigningRequest) -> str:
    """
    Get the subject DN from a CSR.

    Args:
        csr: Parsed CSR

    Returns:
        Subject DN as string (e.g., "CN=user,O=Example")
    """
    return csr.subject.rfc4514_string()


def get_csr_common_name(csr: x509.CertificateSigningRequest) -> Optional[str]:
    """
    Get the Common Name from a CSR's subject.

    Args:
        csr: Parsed CSR

    Returns:
        Common Name or None if not present
    """
    try:
        cn_attrs = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if cn_attrs:
            return cn_attrs[0].value
    except Exception:
        pass
    return None


def get_csr_san(csr: x509.CertificateSigningRequest) -> list:
    """
    Get Subject Alternative Names from a CSR.

    Args:
        csr: Parsed CSR

    Returns:
        List of SAN values as strings
    """
    san_values = []

    try:
        # SANs are in the CSR's extension requests
        for attribute in csr.attributes:
            if attribute.oid == x509.oid.AttributeOID.EXTENSION_REQUEST:
                extensions = attribute.value
                for ext in extensions:
                    if ext.oid == ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
                        san_ext = ext.value
                        for name in san_ext:
                            san_values.append(str(name.value))
    except Exception as e:
        logger.debug(f"Could not extract SAN from CSR: {e}")

    return san_values


def get_csr_key_info(csr: x509.CertificateSigningRequest) -> dict:
    """
    Get key information from a CSR.

    Args:
        csr: Parsed CSR

    Returns:
        Dictionary with key_type, key_size, and key_algorithm
    """
    public_key = csr.public_key()

    if isinstance(public_key, rsa.RSAPublicKey):
        return {
            "key_type": "RSA",
            "key_size": public_key.key_size,
            "key_algorithm": "1.2.840.113549.1.1.1"
        }
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        return {
            "key_type": "EC",
            "key_size": public_key.key_size,
            "key_algorithm": "1.2.840.10045.2.1",
            "curve": public_key.curve.name
        }
    else:
        return {
            "key_type": "Unknown",
            "key_size": 0,
            "key_algorithm": ""
        }


def verify_csr_signature(csr: x509.CertificateSigningRequest) -> bool:
    """
    Verify that the CSR's signature is valid.

    Args:
        csr: Parsed CSR

    Returns:
        True if signature is valid
    """
    try:
        # CSR signature verification is done implicitly during parsing
        # If we got here, the signature is valid
        return csr.is_signature_valid
    except Exception:
        return False


def csr_to_pem(csr: x509.CertificateSigningRequest) -> str:
    """
    Convert CSR to PEM format.

    Args:
        csr: Parsed CSR

    Returns:
        PEM encoded CSR as string
    """
    return csr.public_bytes(Encoding.PEM).decode("utf-8")


def csr_to_der(csr: x509.CertificateSigningRequest) -> bytes:
    """
    Convert CSR to DER format.

    Args:
        csr: Parsed CSR

    Returns:
        DER encoded CSR
    """
    return csr.public_bytes(Encoding.DER)


def csr_to_base64(csr_data: bytes) -> str:
    """
    Convert CSR bytes to base64 string (without PEM headers).

    Args:
        csr_data: CSR in DER or PEM format

    Returns:
        Base64 encoded CSR
    """
    csr = parse_csr(csr_data)
    der_data = csr_to_der(csr)
    return base64.b64encode(der_data).decode("ascii")


def certificate_to_der(cert: x509.Certificate) -> bytes:
    """
    Convert certificate to DER format.

    Args:
        cert: Certificate object

    Returns:
        DER encoded certificate
    """
    return cert.public_bytes(Encoding.DER)


def certificate_to_pem(cert: x509.Certificate) -> str:
    """
    Convert certificate to PEM format.

    Args:
        cert: Certificate object

    Returns:
        PEM encoded certificate as string
    """
    return cert.public_bytes(Encoding.PEM).decode("utf-8")


def create_pkcs7_certs_only(certificates: list) -> bytes:
    """
    Create a PKCS#7 (CMS) structure containing only certificates.

    This is the "degenerate" PKCS#7 format used to return certificate
    chains in MS-WSTEP responses.

    Args:
        certificates: List of certificate DER bytes

    Returns:
        PKCS#7 DER bytes
    """
    certs = [parse_certificate(cert_der) for cert_der in certificates]
    return pkcs7.serialize_certificates(certs, Encoding.DER)


def get_certificate_info(cert: x509.Certificate) -> dict:
    """
    Get information from a certificate.

    Args:
        cert: Certificate object

    Returns:
        Dictionary with certificate details
    """
    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "serial_number": format(cert.serial_number, 'x'),
        "not_before": cert.not_valid_before_utc.isoformat() if hasattr(cert,
                                                                       'not_valid_before_utc') else cert.not_valid_before.isoformat(),
        "not_after": cert.not_valid_after_utc.isoformat() if hasattr(cert,
                                                                     'not_valid_after_utc') else cert.not_valid_after.isoformat(),
        "version": cert.version.value,
    }


def get_certificate_common_name(cert: x509.Certificate) -> Optional[str]:
    """
    Get Common Name from certificate subject.

    Args:
        cert: Certificate object

    Returns:
        Common Name or None
    """
    try:
        cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if cn_attrs:
            return cn_attrs[0].value
    except Exception:
        pass
    return None


def build_subject_dn(cn: str = None, o: str = None, ou: str = None,
                     c: str = None, st: str = None, l: str = None,
                     email: str = None) -> str:
    """
    Build a subject DN string from components.

    Args:
        cn: Common Name
        o: Organization
        ou: Organizational Unit
        c: Country
        st: State/Province
        l: Locality
        email: Email address

    Returns:
        Subject DN string in RFC 4514 format
    """
    parts = []
    if cn:
        parts.append(f"CN={cn}")
    if ou:
        parts.append(f"OU={ou}")
    if o:
        parts.append(f"O={o}")
    if l:
        parts.append(f"L={l}")
    if st:
        parts.append(f"ST={st}")
    if c:
        parts.append(f"C={c}")
    if email:
        parts.append(f"emailAddress={email}")

    return ",".join(parts)


def extract_principal_cn(principal: str) -> str:
    """
    Extract a suitable CN from a Kerberos principal.

    Args:
        principal: Kerberos principal (e.g., "user@DOMAIN.COM" or "host/fqdn@DOMAIN.COM")

    Returns:
        Suitable CN value
    """
    # Remove realm
    if "@" in principal:
        name_part = principal.split("@")[0]
    else:
        name_part = principal

    # Handle service principals (host/fqdn)
    if "/" in name_part:
        parts = name_part.split("/")
        return parts[1] if len(parts) > 1 else parts[0]

    return name_part
