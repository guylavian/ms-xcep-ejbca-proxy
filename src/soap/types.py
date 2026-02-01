"""
SOAP types and XML builders for MS-XCEP and MS-WSTEP protocols.

Uses lxml for direct XML manipulation - more reliable than SOAP frameworks
when dealing with Microsoft's specific SOAP expectations.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from lxml import etree


# XML Namespaces - Microsoft specific
class NS:
    """XML Namespaces used in MS-XCEP and MS-WSTEP protocols."""

    SOAP = "http://www.w3.org/2003/05/soap-envelope"
    SOAP11 = "http://schemas.xmlsoap.org/soap/envelope/"
    WSA = "http://www.w3.org/2005/08/addressing"
    WSSE = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
    WSU = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
    WST = "http://docs.oasis-open.org/ws-sx/ws-trust/200512"
    XCEP = "http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy"
    ENROLLMENT = "http://schemas.microsoft.com/windows/pki/2009/01/enrollment"
    AC = "http://schemas.xmlsoap.org/ws/2006/12/authorization"
    XSI = "http://www.w3.org/2001/XMLSchema-instance"
    XSD = "http://www.w3.org/2001/XMLSchema"


# Namespace map for lxml
NSMAP = {
    "s": NS.SOAP,
    "a": NS.WSA,
    "wsse": NS.WSSE,
    "wsu": NS.WSU,
    "wst": NS.WST,
    "xcep": NS.XCEP,
    "ac": NS.AC,
    "xsi": NS.XSI,
    "xsd": NS.XSD,
}

# SOAP Actions - per TameMyCerts.WSTEP reference implementation
class SoapAction:
    """SOAP Action URIs."""

    XCEP_GET_POLICIES = "http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy/IPolicy/GetPolicies"
    XCEP_GET_POLICIES_RESPONSE = "http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy/IPolicy/GetPoliciesResponse"
    WSTEP_RST = "http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RST/wstep"
    # Note: RSTRC = RequestSecurityTokenResponseCollection (per MS-WSTEP spec)
    WSTEP_RSTRC = "http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RSTRC/wstep"
    # Legacy alias for backwards compatibility
    WSTEP_RSTR = WSTEP_RSTRC


# Token Types
class TokenType:
    """Token type URIs."""

    PKCS10 = "http://schemas.microsoft.com/windows/pki/2009/01/enrollment#PKCS10"
    PKCS7 = "http://schemas.microsoft.com/windows/pki/2009/01/enrollment#PKCS7"
    X509V3 = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3"
    BASE64_BINARY = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#base64binary"


# Policy Schemas
class PolicySchema:
    """Policy schema identifiers."""

    # Certificate request schemas
    PKCS10 = 1
    PKCS7 = 2
    CMC = 3


# Private Key Flags
class PrivateKeyFlags(Enum):
    """Private key flags for certificate templates."""

    EXPORTABLE = 0x00000001
    STRONG_KEY_PROTECTION = 0x00000002
    ARCHIVAL = 0x00000004
    EK_TRUST_ON_USE = 0x00000008
    EK_VALIDATE_CERT = 0x00000010
    EK_VALIDATE_KEY = 0x00000020
    ATTEST_PREFERRED = 0x00000040
    ATTEST_REQUIRED = 0x00000080
    ATTEST_NONE = 0x00000000


# Subject Name Flags
class SubjectNameFlags(Enum):
    """Subject name flags for certificate templates."""

    ENROLLEE_SUPPLIES_SUBJECT = 0x00000001
    ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME = 0x00010000
    SUBJECT_ALT_REQUIRE_DOMAIN_DNS = 0x00400000
    SUBJECT_ALT_REQUIRE_SPN = 0x00800000
    SUBJECT_ALT_REQUIRE_DIRECTORY_GUID = 0x01000000
    SUBJECT_ALT_REQUIRE_UPN = 0x02000000
    SUBJECT_ALT_REQUIRE_EMAIL = 0x04000000
    SUBJECT_ALT_REQUIRE_DNS = 0x08000000
    SUBJECT_REQUIRE_DNS_AS_CN = 0x10000000
    SUBJECT_REQUIRE_EMAIL = 0x20000000
    SUBJECT_REQUIRE_COMMON_NAME = 0x40000000
    SUBJECT_REQUIRE_DIRECTORY_PATH = 0x80000000


# Enrollment Flags
class EnrollmentFlags(Enum):
    """Enrollment flags for certificate templates."""

    INCLUDE_SYMMETRIC_ALGORITHMS = 0x00000001
    PEND_ALL_REQUESTS = 0x00000002
    PUBLISH_TO_KRA_CONTAINER = 0x00000004
    PUBLISH_TO_DS = 0x00000008
    AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE = 0x00000010
    AUTO_ENROLLMENT = 0x00000020
    PREVIOUS_APPROVAL_VALIDATE_REENROLLMENT = 0x00000040
    USER_INTERACTION_REQUIRED = 0x00000100
    REMOVE_INVALID_CERTIFICATE_FROM_PERSONAL_STORE = 0x00000400
    ALLOW_ENROLL_ON_BEHALF_OF = 0x00000800
    ADD_OCSP_NOCHECK = 0x00001000
    ENABLE_KEY_REUSE_ON_NT_TOKEN_KEYSET_STORAGE_FULL = 0x00002000
    NOREVOCATION_INFOIN_CERTS = 0x00004000
    INCLUDE_BASIC_CONSTRAINTS_FOR_EE_CERTS = 0x00008000
    ALLOW_PREVIOUS_APPROVAL_KEYBASEDRENEWAL_VALIDATE_REENROLLMENT = 0x00010000
    ISSUANCE_POLICIES_FROM_REQUEST = 0x00020000


@dataclass
class OID:
    """Object Identifier definition."""

    oid: str
    name: str
    group: int = 0
    reference_id: int = 0  # oIDReferenceID (unique per OID)
    default_name: Optional[str] = None


@dataclass
class CryptoProvider:
    """Cryptographic provider definition."""

    name: str
    algorithm_oid: str = "1.2.840.113549.1.1.1"  # RSA
    algorithm_name: str = "RSA"


@dataclass
class PrivateKeyAttributes:
    """Private key attributes for certificate templates."""

    min_key_length: int = 2048
    key_spec: int = 1  # AT_KEYEXCHANGE
    key_usage_property: int = 0
    permissions: int = 0
    algorithm_oid: str = "1.2.840.113549.1.1.1"
    crypto_providers: list = field(default_factory=list)


@dataclass
class CertificateValidity:
    """Certificate validity period."""

    validity_period_seconds: int = 31536000  # 1 year
    renewal_period_seconds: int = 5184000   # 60 days


@dataclass
class SupersededPolicies:
    """Policies superseded by this policy."""

    policy_oids: list = field(default_factory=list)


@dataclass
class RARequirements:
    """Registration Authority requirements."""

    ra_signatures: int = 0
    ra_eku_oids: list = field(default_factory=list)
    ra_policies: list = field(default_factory=list)


@dataclass
class KeyArchivalAttributes:
    """Key archival attributes."""

    symmetric_algorithm_oid: str = ""
    symmetric_algorithm_key_length: int = 0


@dataclass
class Extension:
    """Certificate extension definition."""

    oid: str
    critical: bool = False
    value: bytes = b""


@dataclass
class CertificatePolicy:
    """Certificate enrollment policy definition."""

    policy_oid: str
    certificate_validity: CertificateValidity
    common_name: str = ""

    # Permission flags
    permission_enroll: bool = True
    permission_auto_enroll: bool = False

    # Private key settings
    private_key_attributes: PrivateKeyAttributes = field(default_factory=PrivateKeyAttributes)
    private_key_flags: int = 0

    # Subject name settings
    subject_name_flags: int = 0

    # Enrollment settings
    enrollment_flags: int = 0

    # RA requirements
    ra_requirements: RARequirements = field(default_factory=RARequirements)

    # Key archival
    key_archival_attributes: KeyArchivalAttributes = field(default_factory=KeyArchivalAttributes)

    # Extensions
    extensions: list = field(default_factory=list)

    # Attributes
    attributes: list = field(default_factory=list)

    # Hash algorithm
    hash_algorithm_oid: str = "2.16.840.1.101.3.4.2.1"  # SHA-256

    # Superseded policies
    superseded_policies: SupersededPolicies = field(default_factory=SupersededPolicies)


@dataclass
class CAInfo:
    """Certificate Authority information."""

    ca_reference: int  # CAReference ID
    ca_uri: str
    certificate: bytes  # DER encoded CA certificate
    renewal_only: bool = False


@dataclass
class PolicyResponse:
    """Complete policy response structure."""

    policy_id: str
    policy_friendly_name: str
    policies: list  # List of CertificatePolicy
    cas: list  # List of CAInfo
    oids: list  # List of OID
    next_update_hours: Optional[int] = 8  # Hours until client should refresh policies


class SoapBuilder:
    """Builder for SOAP messages."""

    @staticmethod
    def create_envelope() -> etree._Element:
        """Create a SOAP 1.2 envelope."""
        return etree.Element(
            f"{{{NS.SOAP}}}Envelope",
            nsmap=NSMAP
        )

    @staticmethod
    def add_header(envelope: etree._Element, action: str, message_id: str = None,
                   relates_to: str = None) -> etree._Element:
        """Add SOAP header with WS-Addressing."""
        header = etree.SubElement(envelope, f"{{{NS.SOAP}}}Header")

        # Action
        action_elem = etree.SubElement(header, f"{{{NS.WSA}}}Action")
        action_elem.set(f"{{{NS.SOAP}}}mustUnderstand", "1")
        action_elem.text = action

        # RelatesTo (for responses)
        if relates_to:
            relates = etree.SubElement(header, f"{{{NS.WSA}}}RelatesTo")
            relates.text = relates_to

        return header

    @staticmethod
    def add_timestamp(security: etree._Element, created: datetime = None,
                      expires_in_seconds: int = 300) -> etree._Element:
        """Add WS-Security timestamp."""
        if created is None:
            created = datetime.now(timezone.utc)

        expires = datetime.fromtimestamp(
            created.timestamp() + expires_in_seconds,
            tz=timezone.utc
        )

        timestamp = etree.SubElement(security, f"{{{NS.WSU}}}Timestamp")
        timestamp.set(f"{{{NS.WSU}}}Id", "_0")

        created_elem = etree.SubElement(timestamp, f"{{{NS.WSU}}}Created")
        created_elem.text = created.strftime("%Y-%m-%dT%H:%M:%S.000Z")

        expires_elem = etree.SubElement(timestamp, f"{{{NS.WSU}}}Expires")
        expires_elem.text = expires.strftime("%Y-%m-%dT%H:%M:%S.000Z")

        return timestamp

    @staticmethod
    def add_body(envelope: etree._Element) -> etree._Element:
        """Add SOAP body."""
        body = etree.SubElement(envelope, f"{{{NS.SOAP}}}Body")
        body.set(f"{{{NS.XSI}}}type", "xsd:string")
        return body

    @staticmethod
    def create_soap_fault(code: str, reason: str, detail: str = None) -> etree._Element:
        """Create a SOAP fault response."""
        envelope = SoapBuilder.create_envelope()
        body = etree.SubElement(envelope, f"{{{NS.SOAP}}}Body")

        fault = etree.SubElement(body, f"{{{NS.SOAP}}}Fault")

        code_elem = etree.SubElement(fault, f"{{{NS.SOAP}}}Code")
        value_elem = etree.SubElement(code_elem, f"{{{NS.SOAP}}}Value")
        value_elem.text = f"s:{code}"

        reason_elem = etree.SubElement(fault, f"{{{NS.SOAP}}}Reason")
        text_elem = etree.SubElement(reason_elem, f"{{{NS.SOAP}}}Text")
        text_elem.set("{http://www.w3.org/XML/1998/namespace}lang", "en-US")
        text_elem.text = reason

        if detail:
            detail_elem = etree.SubElement(fault, f"{{{NS.SOAP}}}Detail")
            detail_elem.text = detail

        return envelope


class SoapParser:
    """Parser for incoming SOAP messages."""

    @staticmethod
    def parse(xml_bytes: bytes) -> etree._Element:
        """Parse SOAP XML from bytes."""
        return etree.fromstring(xml_bytes)

    @staticmethod
    def get_action(envelope: etree._Element, http_soap_action: Optional[str] = None) -> Optional[str]:
        """Extract SOAP Action from header, with HTTP SOAPAction header fallback.
        
        Args:
            envelope: Parsed SOAP envelope
            http_soap_action: Optional SOAPAction HTTP header value as fallback
            
        Returns:
            The SOAP action URI, or None if not found
        """
        # Try WS-Addressing Action first
        action = envelope.find(f".//{{{NS.WSA}}}Action")
        if action is not None and action.text:
            return action.text.strip()
        
        # Fallback to HTTP SOAPAction header
        if http_soap_action:
            # SOAPAction header may be quoted
            action_value = http_soap_action.strip().strip('"')
            if action_value:
                return action_value
        
        return None

    @staticmethod
    def get_message_id(envelope: etree._Element) -> Optional[str]:
        """Extract MessageID from header."""
        msg_id = envelope.find(f".//{{{NS.WSA}}}MessageID")
        if msg_id is not None:
            return msg_id.text.strip() if msg_id.text else None
        return None

    @staticmethod
    def get_body(envelope: etree._Element) -> Optional[etree._Element]:
        """Get SOAP body element."""
        # Try SOAP 1.2 first, then SOAP 1.1
        body = envelope.find(f"{{{NS.SOAP}}}Body")
        if body is None:
            body = envelope.find(f"{{{NS.SOAP11}}}Body")
        return body

    @staticmethod
    def get_security_token(envelope: etree._Element) -> Optional[str]:
        """Extract BinarySecurityToken from WS-Security header."""
        token = envelope.find(f".//{{{NS.WSSE}}}BinarySecurityToken")
        if token is not None:
            return token.text
        return None

    @staticmethod
    def get_username_token(envelope: etree._Element) -> tuple:
        """Extract username/password from WS-Security header."""
        username_elem = envelope.find(f".//{{{NS.WSSE}}}Username")
        password_elem = envelope.find(f".//{{{NS.WSSE}}}Password")

        username = username_elem.text if username_elem is not None else None
        password = password_elem.text if password_elem is not None else None

        return username, password


def serialize_xml(element: etree._Element, pretty_print: bool = False) -> bytes:
    """Serialize XML element to bytes."""
    return etree.tostring(
        element,
        encoding="utf-8",
        xml_declaration=True,
        pretty_print=pretty_print
    )


def create_nil_element(parent: etree._Element, tag: str, namespace: str) -> etree._Element:
    """Create an element with xsi:nil='true'."""
    elem = etree.SubElement(parent, f"{{{namespace}}}{tag}")
    elem.set(f"{{{NS.XSI}}}nil", "true")
    return elem
