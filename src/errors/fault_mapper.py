"""
SOAP Fault mapping utilities.

Maps domain exceptions to proper SOAP 1.2 faults for MS-XCEP/WSTEP responses.
"""

from dataclasses import dataclass
from typing import Optional, Type
from lxml import etree

from .exceptions import (
    ProxyError,
    AuthenticationError,
    AuthorizationError,
    EnrollmentError,
    ValidationError,
    CAError,
    CAConnectionError,
    CAValidationError,
    LDAPError,
    TemplateError,
    TemplateNotFoundError,
)


# SOAP 1.2 namespaces
NS_SOAP = "http://www.w3.org/2003/05/soap-envelope"
NS_WSA = "http://www.w3.org/2005/08/addressing"
NS_WSSE = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"

NSMAP = {
    "s": NS_SOAP,
    "a": NS_WSA,
}


@dataclass
class SoapFault:
    """
    SOAP 1.2 Fault structure.

    Attributes:
        code: Fault code (s:Sender or s:Receiver)
        subcode: Optional subcode URI
        reason: Human-readable fault reason
        detail: Optional detailed error information
        node: Optional node that generated the fault
    """
    code: str  # "Sender" or "Receiver"
    reason: str
    subcode: Optional[str] = None
    detail: Optional[str] = None
    node: Optional[str] = None

    def to_xml(self, message_id: Optional[str] = None,
               relates_to: Optional[str] = None,
               action: Optional[str] = None) -> bytes:
        """
        Serialize to SOAP 1.2 Fault envelope.

        Args:
            message_id: WS-Addressing MessageID for response
            relates_to: WS-Addressing RelatesTo (original request ID)
            action: WS-Addressing Action for response

        Returns:
            SOAP envelope bytes
        """
        # Create envelope
        envelope = etree.Element(f"{{{NS_SOAP}}}Envelope", nsmap=NSMAP)

        # Header with WS-Addressing
        header = etree.SubElement(envelope, f"{{{NS_SOAP}}}Header")

        if action:
            action_elem = etree.SubElement(header, f"{{{NS_WSA}}}Action")
            action_elem.set(f"{{{NS_SOAP}}}mustUnderstand", "1")
            action_elem.text = action

        if relates_to:
            relates_elem = etree.SubElement(header, f"{{{NS_WSA}}}RelatesTo")
            relates_elem.text = relates_to

        if message_id:
            msg_id_elem = etree.SubElement(header, f"{{{NS_WSA}}}MessageID")
            msg_id_elem.text = message_id

        # Body with Fault
        body = etree.SubElement(envelope, f"{{{NS_SOAP}}}Body")
        fault = etree.SubElement(body, f"{{{NS_SOAP}}}Fault")

        # Code (required)
        code_elem = etree.SubElement(fault, f"{{{NS_SOAP}}}Code")
        value_elem = etree.SubElement(code_elem, f"{{{NS_SOAP}}}Value")
        value_elem.text = f"s:{self.code}"

        # Subcode (optional)
        if self.subcode:
            subcode_elem = etree.SubElement(code_elem, f"{{{NS_SOAP}}}Subcode")
            sub_value = etree.SubElement(subcode_elem, f"{{{NS_SOAP}}}Value")
            sub_value.text = self.subcode

        # Reason (required)
        reason_elem = etree.SubElement(fault, f"{{{NS_SOAP}}}Reason")
        text_elem = etree.SubElement(reason_elem, f"{{{NS_SOAP}}}Text")
        text_elem.set("{http://www.w3.org/XML/1998/namespace}lang", "en")
        text_elem.text = self.reason

        # Node (optional)
        if self.node:
            node_elem = etree.SubElement(fault, f"{{{NS_SOAP}}}Node")
            node_elem.text = self.node

        # Detail (optional)
        if self.detail:
            detail_elem = etree.SubElement(fault, f"{{{NS_SOAP}}}Detail")
            detail_text = etree.SubElement(detail_elem, "ErrorDetail")
            detail_text.text = self.detail

        return etree.tostring(
            envelope,
            encoding="utf-8",
            xml_declaration=True
        )


class FaultMapper:
    """
    Maps domain exceptions to SOAP faults.

    Usage:
        fault = FaultMapper.from_exception(my_error)
        response_bytes = fault.to_xml(relates_to=request_message_id)
    """

    # Default fault action for XCEP/WSTEP
    DEFAULT_FAULT_ACTION = "http://www.w3.org/2005/08/addressing/soap/fault"

    @classmethod
    def from_exception(cls, exc: Exception, include_detail: bool = False) -> SoapFault:
        """
        Create SoapFault from exception.

        Args:
            exc: Exception to map
            include_detail: Include exception details (disable in production)

        Returns:
            SoapFault instance
        """
        if isinstance(exc, ProxyError):
            return cls._map_proxy_error(exc, include_detail)
        else:
            # Generic server error for unexpected exceptions
            return SoapFault(
                code="Receiver",
                reason="Internal server error",
                detail=str(exc) if include_detail else None
            )

    @classmethod
    def _map_proxy_error(cls, exc: ProxyError, include_detail: bool) -> SoapFault:
        """Map ProxyError to SoapFault."""
        detail = None
        if include_detail and exc.context and exc.context.details:
            detail = exc.context.details

        # Map specific error types to appropriate fault messages
        if isinstance(exc, AuthenticationError):
            return SoapFault(
                code="Sender",
                reason="Authentication required",
                subcode="wsse:FailedAuthentication",
                detail=detail
            )

        if isinstance(exc, AuthorizationError):
            return SoapFault(
                code="Sender",
                reason=f"Access denied: {exc.message}",
                detail=detail
            )

        if isinstance(exc, TemplateNotFoundError):
            return SoapFault(
                code="Sender",
                reason=f"Certificate template not found: {exc.message}",
                detail=detail
            )

        if isinstance(exc, TemplateError):
            return SoapFault(
                code="Sender",
                reason=f"Template error: {exc.message}",
                detail=detail
            )

        if isinstance(exc, ValidationError):
            return SoapFault(
                code="Sender",
                reason=f"Validation error: {exc.message}",
                detail=detail
            )

        if isinstance(exc, CAValidationError):
            return SoapFault(
                code="Sender",
                reason=f"CA rejected request: {exc.message}",
                detail=detail
            )

        if isinstance(exc, CAConnectionError):
            return SoapFault(
                code="Receiver",
                reason="Certificate authority unavailable",
                detail=detail
            )

        if isinstance(exc, CAError):
            return SoapFault(
                code="Receiver",
                reason=f"CA error: {exc.message}",
                detail=detail
            )

        if isinstance(exc, LDAPError):
            return SoapFault(
                code="Receiver",
                reason="Directory service error",
                detail=detail
            )

        if isinstance(exc, EnrollmentError):
            return SoapFault(
                code="Receiver",
                reason=f"Enrollment failed: {exc.message}",
                detail=detail
            )

        # Default for other ProxyErrors
        return SoapFault(
            code=exc.soap_fault_code,
            reason=exc.message,
            detail=detail
        )

    @classmethod
    def create_fault_response(
        cls,
        exc: Exception,
        relates_to: Optional[str] = None,
        include_detail: bool = False
    ) -> bytes:
        """
        Create complete SOAP fault response from exception.

        Args:
            exc: Exception to map
            relates_to: WS-Addressing MessageID of original request
            include_detail: Include exception details

        Returns:
            SOAP envelope bytes
        """
        import uuid
        fault = cls.from_exception(exc, include_detail)
        return fault.to_xml(
            message_id=f"urn:uuid:{uuid.uuid4()}",
            relates_to=relates_to,
            action=cls.DEFAULT_FAULT_ACTION
        )
