"""
MS-WSTEP (WS-Trust X.509v3 Token Enrollment Extensions) Service Implementation.

Handles RequestSecurityToken requests from Windows clients for certificate
enrollment and returns issued certificates from EJBCA.

Reference: [MS-WSTEP] - WS-Trust X.509v3 Token Enrollment Extensions
https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wstep/
"""

import base64
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Optional
from lxml import etree

from .types import (
    NS, NSMAP, SoapAction, TokenType, SoapBuilder, SoapParser,
    serialize_xml, create_nil_element
)

logger = logging.getLogger(__name__)


class RequestType(Enum):
    """WS-Trust request types."""

    ISSUE = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue"
    RENEW = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Renew"
    VALIDATE = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Validate"


class DispositionStatus(Enum):
    """Certificate request disposition status."""

    ISSUED = "issued"
    PENDING = "pending"
    DENIED = "denied"
    ERROR = "error"


@dataclass
class RequestContext:
    """Additional context from the enrollment request."""

    device_type: Optional[str] = None
    application_version: Optional[str] = None
    device_id: Optional[str] = None
    certificate_template: Optional[str] = None
    enrollment_type: Optional[str] = None
    request_version: Optional[str] = None


@dataclass
class SecurityTokenRequest:
    """Parsed RequestSecurityToken."""

    message_id: str
    request_type: RequestType
    csr_data: bytes  # Raw PKCS#10 CSR data
    token_type: str
    context: RequestContext
    binary_security_token: Optional[str] = None  # For renewal


@dataclass
class EnrollmentResult:
    """Result of certificate enrollment."""

    status: DispositionStatus
    certificate: Optional[bytes] = None  # DER encoded certificate
    certificate_chain: Optional[list] = None  # List of DER encoded certs
    request_id: Optional[str] = None
    error_message: Optional[str] = None
    disposition_message: Optional[str] = None


class WSTEPService:
    """
    MS-WSTEP Certificate Enrollment Service.

    Implements the RequestSecurityToken operation that Windows clients
    use to request certificate enrollment.
    """

    # Context item names
    CONTEXT_DEVICE_TYPE = "DeviceType"
    CONTEXT_APPLICATION_VERSION = "ApplicationVersion"
    CONTEXT_DEVICE_ID = "DeviceId"
    CONTEXT_CERTIFICATE_TEMPLATE = "CertificateTemplate"
    CONTEXT_ENROLLMENT_TYPE = "EnrollmentType"
    CONTEXT_REQUEST_VERSION = "RequestVersion"

    def __init__(self, enrollment_handler):
        """
        Initialize WSTEP service.

        Args:
            enrollment_handler: Object that handles certificate enrollment
                                (sends CSR to EJBCA and returns certificate)
        """
        self.enrollment_handler = enrollment_handler

    def handle_request(self, request_xml: bytes, client_identity: str,
                        client_ip: str = "", http_soap_action: Optional[str] = None) -> bytes:
        """
        Handle incoming SOAP request.

        Args:
            request_xml: Raw SOAP request XML
            client_identity: Authenticated client principal (from Kerberos)
            client_ip: Client IP address for audit logging
            http_soap_action: Optional SOAPAction HTTP header for fallback

        Returns:
            SOAP response XML bytes
        """
        try:
            envelope = SoapParser.parse(request_xml)
            action = SoapParser.get_action(envelope, http_soap_action)

            if action == SoapAction.WSTEP_RST:
                return self._handle_request_security_token(envelope, client_identity, client_ip)
            else:
                logger.warning(f"Unknown SOAP action: {action}")
                return self._create_fault(
                    "Sender",
                    f"Unknown action: {action}",
                    "InvalidAction"
                )

        except etree.XMLSyntaxError as e:
            logger.error(f"XML parse error: {e}")
            return self._create_fault("Sender", "Invalid XML request", "XMLParseError")
        except ValueError as e:
            logger.error(f"Invalid request: {e}")
            return self._create_fault("Sender", str(e), "InvalidRequest")
        except Exception as e:
            logger.exception(f"Error handling WSTEP request: {e}")
            return self._create_fault("Receiver", "Internal server error", "InternalError")

    def _handle_request_security_token(self, envelope: etree._Element,
                                       client_identity: str,
                                       client_ip: str = "") -> bytes:
        """Handle RequestSecurityToken request."""
        # Check if enrollment handler is available
        if not self.enrollment_handler:
            return self._create_fault(
                "Receiver",
                "Certificate enrollment service not available",
                "ServiceUnavailable"
            )

        request = self._parse_request_security_token(envelope)
        message_id = SoapParser.get_message_id(envelope)

        logger.info(
            f"RequestSecurityToken from {client_identity}, "
            f"message_id={message_id}, "
            f"template={request.context.certificate_template}, "
            f"request_type={request.request_type.value}"
        )

        # Determine certificate template
        template_name = request.context.certificate_template
        if not template_name:
            # Try to infer from device type
            if request.context.device_type == "CIMClient_Windows":
                template_name = "Computer"
            else:
                template_name = "User"

        # Enroll certificate via EJBCA
        result = self.enrollment_handler.enroll(
            csr_data=request.csr_data,
            client_identity=client_identity,
            template_name=template_name,
            request_type=request.request_type,
            client_ip=client_ip
        )

        # Build response
        response = self._build_request_security_token_response(
            result=result,
            relates_to=message_id,
            context=request.context
        )

        return serialize_xml(response)

    def _parse_request_security_token(self,
                                       envelope: etree._Element) -> SecurityTokenRequest:
        """Parse RequestSecurityToken request elements."""
        body = SoapParser.get_body(envelope)
        message_id = SoapParser.get_message_id(envelope)

        # Find RequestSecurityToken element
        rst = body.find(f".//{{{NS.WST}}}RequestSecurityToken")
        if rst is None:
            raise ValueError("Missing RequestSecurityToken element")

        # Parse TokenType
        token_type_elem = rst.find(f"{{{NS.WST}}}TokenType")
        token_type = token_type_elem.text if token_type_elem is not None else TokenType.X509V3

        # Parse RequestType
        request_type_elem = rst.find(f"{{{NS.WST}}}RequestType")
        request_type_str = request_type_elem.text if request_type_elem is not None else RequestType.ISSUE.value
        try:
            request_type = RequestType(request_type_str)
        except ValueError:
            request_type = RequestType.ISSUE

        # Parse BinarySecurityToken (PKCS#10 CSR)
        bst = rst.find(f".//{{{NS.WSSE}}}BinarySecurityToken")
        if bst is None:
            raise ValueError("Missing BinarySecurityToken with CSR")

        value_type = bst.get("ValueType", "")
        if TokenType.PKCS10 not in value_type and "PKCS10" not in value_type:
            logger.warning(f"Unexpected ValueType: {value_type}, expected PKCS10")

        csr_b64 = bst.text
        if not csr_b64:
            raise ValueError("Empty BinarySecurityToken")

        try:
            csr_data = base64.b64decode(csr_b64)
        except Exception as e:
            raise ValueError(f"Invalid base64 in CSR: {e}")

        # Parse AdditionalContext
        context = self._parse_additional_context(rst)

        return SecurityTokenRequest(
            message_id=message_id,
            request_type=request_type,
            csr_data=csr_data,
            token_type=token_type,
            context=context
        )

    def _parse_additional_context(self, rst: etree._Element) -> RequestContext:
        """Parse AdditionalContext element."""
        context = RequestContext()

        ac = rst.find(f".//{{{NS.AC}}}AdditionalContext")
        if ac is None:
            return context

        for item in ac.findall(f"{{{NS.AC}}}ContextItem"):
            name = item.get("Name", "")
            value_elem = item.find(f"{{{NS.AC}}}Value")
            value = value_elem.text if value_elem is not None else None

            if name == self.CONTEXT_DEVICE_TYPE:
                context.device_type = value
            elif name == self.CONTEXT_APPLICATION_VERSION:
                context.application_version = value
            elif name == self.CONTEXT_DEVICE_ID:
                context.device_id = value
            elif name == self.CONTEXT_CERTIFICATE_TEMPLATE:
                context.certificate_template = value
            elif name == self.CONTEXT_ENROLLMENT_TYPE:
                context.enrollment_type = value
            elif name == self.CONTEXT_REQUEST_VERSION:
                context.request_version = value

        return context

    def _build_request_security_token_response(
        self,
        result: EnrollmentResult,
        relates_to: str = None,
        context: RequestContext = None
    ) -> etree._Element:
        """
        Build RequestSecurityTokenResponse SOAP message.

        Structure per TameMyCerts.WSTEP/MS-WSTEP spec:
        - RequestSecurityTokenResponseCollection
          - RequestSecurityTokenResponse
            - TokenType
            - DispositionMessage
            - RequestedSecurityToken
              - BinarySecurityToken (PKCS#7 with cert chain)
            - RequestID
        """
        envelope = SoapBuilder.create_envelope()
        SoapBuilder.add_header(
            envelope,
            action=SoapAction.WSTEP_RSTRC,  # Use RSTRC (Collection) action
            relates_to=relates_to
        )

        body = etree.SubElement(envelope, f"{{{NS.SOAP}}}Body")

        # RequestSecurityTokenResponseCollection for WSTEP
        rstr_collection = etree.SubElement(
            body,
            f"{{{NS.WST}}}RequestSecurityTokenResponseCollection"
        )

        rstr = etree.SubElement(
            rstr_collection,
            f"{{{NS.WST}}}RequestSecurityTokenResponse"
        )

        # TokenType - always X509v3 per MS-WSTEP spec
        token_type = etree.SubElement(rstr, f"{{{NS.WST}}}TokenType")
        token_type.text = TokenType.X509V3

        if result.status == DispositionStatus.ISSUED:
            # DispositionMessage - "Issued" per TameMyCerts/AD CS
            disp_msg = etree.SubElement(
                rstr,
                f"{{{NS.ENROLLMENT}}}DispositionMessage"
            )
            disp_msg.text = result.disposition_message or "Issued"

            # RequestedSecurityToken
            rst_elem = etree.SubElement(rstr, f"{{{NS.WST}}}RequestedSecurityToken")

            # BinarySecurityToken with issued certificate in PKCS#7 format
            # Per cepces wstep/types.py - ValueType indicates the format
            bst = etree.SubElement(rst_elem, f"{{{NS.WSSE}}}BinarySecurityToken")
            bst.set("ValueType", TokenType.PKCS7)
            bst.set("EncodingType", TokenType.BASE64_BINARY)

            # Create PKCS#7 envelope with certificate chain
            pkcs7_data = self._create_pkcs7_response(
                result.certificate,
                result.certificate_chain
            )
            bst.text = base64.b64encode(pkcs7_data).decode("ascii")

            # RequestID - per MS-WSTEP, this is an integer request ID
            request_id = etree.SubElement(
                rstr,
                f"{{{NS.ENROLLMENT}}}RequestID"
            )
            request_id.text = result.request_id or "0"

        elif result.status == DispositionStatus.PENDING:
            # Pending status - return RequestID for polling
            disp_msg = etree.SubElement(
                rstr,
                f"{{{NS.ENROLLMENT}}}DispositionMessage"
            )
            disp_msg.text = result.disposition_message or "Request pending approval"

            request_id = etree.SubElement(
                rstr,
                f"{{{NS.ENROLLMENT}}}RequestID"
            )
            request_id.text = result.request_id or "0"

        elif result.status == DispositionStatus.DENIED:
            # Denied - return error
            disp_msg = etree.SubElement(
                rstr,
                f"{{{NS.ENROLLMENT}}}DispositionMessage"
            )
            disp_msg.text = result.disposition_message or "Request denied"

        else:
            # Error - return error
            disp_msg = etree.SubElement(
                rstr,
                f"{{{NS.ENROLLMENT}}}DispositionMessage"
            )
            disp_msg.text = result.error_message or "Enrollment failed"

        return envelope

    def _create_pkcs7_response(self, certificate: bytes,
                               chain: Optional[list] = None) -> bytes:
        """
        Create PKCS#7 (CMS) envelope containing the certificate chain.

        Windows expects the response in PKCS#7 SignedData format containing
        the issued certificate and the CA chain.

        We build a degenerate SignedData (certs-only, no signers).  If Windows
        rejects this, we can switch to pyasn1/pyasn1-modules or openssl to
        create a fully-formed CMS SignedData with an empty SignerInfos SET.
        """
        from cryptography import x509
        from cryptography.hazmat.primitives.serialization import pkcs7, Encoding

        # Parse the issued certificate
        cert = x509.load_der_x509_certificate(certificate)

        # Parse chain certificates
        chain_certs = []
        if chain:
            for cert_der in chain:
                try:
                    chain_certs.append(x509.load_der_x509_certificate(cert_der))
                except Exception as e:
                    logger.warning(f"Failed to parse chain cert: {e}")

        # All certificates: issued cert first, then chain
        all_certs = [cert] + chain_certs

        # Serialize as PKCS#7 certs-only (degenerate SignedData)
        # cryptography >= 37 provides serialize_certificates for this purpose.
        try:
            pkcs7_data = pkcs7.serialize_certificates(all_certs, Encoding.DER)
        except Exception as e:
            # Fallback: return raw DER cert if PKCS#7 serialization fails
            logger.error(f"PKCS#7 serialization failed, returning raw cert: {e}")
            pkcs7_data = certificate

        return pkcs7_data

    def _create_fault(self, code: str, reason: str,
                      subcode: str = None) -> bytes:
        """Create SOAP fault response with optional subcode."""
        envelope = SoapBuilder.create_envelope()
        body = etree.SubElement(envelope, f"{{{NS.SOAP}}}Body")

        fault = etree.SubElement(body, f"{{{NS.SOAP}}}Fault")

        # Code
        code_elem = etree.SubElement(fault, f"{{{NS.SOAP}}}Code")
        value_elem = etree.SubElement(code_elem, f"{{{NS.SOAP}}}Value")
        value_elem.text = f"s:{code}"

        if subcode:
            subcode_elem = etree.SubElement(code_elem, f"{{{NS.SOAP}}}Subcode")
            subvalue_elem = etree.SubElement(subcode_elem, f"{{{NS.SOAP}}}Value")
            subvalue_elem.text = f"enrollment:{subcode}"

        # Reason
        reason_elem = etree.SubElement(fault, f"{{{NS.SOAP}}}Reason")
        text_elem = etree.SubElement(reason_elem, f"{{{NS.SOAP}}}Text")
        text_elem.set("{http://www.w3.org/XML/1998/namespace}lang", "en-US")
        text_elem.text = reason

        return serialize_xml(envelope)
