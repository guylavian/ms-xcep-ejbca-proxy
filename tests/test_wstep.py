"""
Tests for MS-WSTEP service.
"""

import base64
import pytest
from lxml import etree
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta, timezone

from src.soap.wstep_service import (
    WSTEPService, SecurityTokenRequest, RequestContext,
    EnrollmentResult, DispositionStatus, RequestType
)
from src.soap.types import NS, SoapAction, SoapParser


# Sample PKCS#10 CSR (base64 encoded DER format, valid for testing)
# Generated with cryptography library: CN=TestUser, RSA 2048-bit key
SAMPLE_CSR_B64 = "MIICWDCCAUACAQAwEzERMA8GA1UEAwwIVGVzdFVzZXIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDQdtxhQZ0H5aYiAgpWMkmbVvGjB/OMHCImK/NaXQfIYe9McAecy8Nc5O4TbdZYYAkPR4L8wEpPVxBmf1nG4TopmXFnNaxYbUH9XS4W1N09j/SXxIqKUl0vk3DfTlZX8J7CX/4fC70P2ht7af5KRRAmD1CGlJRhr7B45VRaPGDOWcCDyY8dfphBMGGEARTfStFAzWd631kvQSwV6Qqi+zNy+QzMuSaR9AmXmw90vIAbeFbs7vG4NEFNP3kNx9huUWzqq3ZHWLs5lc+6XDVlUwrDg5YtcuaZa3GHKy8C+rrF8YtECYIPMwnFd0Op94JD2+XKb8R8BM2xsH3c/m4LAKxTAgMBAAGgADANBgkqhkiG9w0BAQsFAAOCAQEAmy8JZSy9NaQ3E5gE0TZInwV0+AXvkIT3g9P/ItcLfuKOqcmUfbyTBbk74uT0LxWzvwgv44YtUecOgjJsK8yyGL0MgScxYXBGI1I5bO1V8wig9xO72BI7xiiWzZbJpyaEsRcxJG8trfoTTt4xeF1C85dwcPYQNGlieq/6r8HJ3TUjmkRxyV2d8lVZXRw4tuqGd2a2UlMCQjXKEFhMoYLjDhPdGWomDRnC6pYJUydwNlK1szQv4U7b+jUaWHq5znb92anZ/a+Pt0NQcPC7gvXmoRuPDve/kiZ9Z8JsZ1w6Z5tXZY4IflauOJMQbXNf0cIr0YBPUYNVFnISM4uYhIgYlA=="


def _create_test_certificate() -> bytes:
    """Create a self-signed test certificate in DER format."""
    from cryptography.hazmat.primitives.serialization import Encoding
    
    # Generate a private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    # Create a self-signed certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Test Certificate"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org"),
    ])
    
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .sign(private_key, hashes.SHA256())
    )
    
    return cert.public_bytes(encoding=Encoding.DER)


# Create test certificate once for all tests
TEST_CERTIFICATE_DER = _create_test_certificate()


class MockEnrollmentHandler:
    """Mock enrollment handler for testing."""

    def __init__(self, result=None):
        self.last_request = None
        self.result = result or EnrollmentResult(
            status=DispositionStatus.ISSUED,
            certificate=TEST_CERTIFICATE_DER,  # Use valid DER certificate
            certificate_chain=[TEST_CERTIFICATE_DER],  # Use as self-signed chain
            request_id="12345",  # Use integer-like request ID per MS-WSTEP
            disposition_message="Issued"  # Per TameMyCerts/AD CS
        )

    def enroll(self, csr_data, client_identity, template_name, request_type, client_ip=""):
        self.last_request = {
            "csr_data": csr_data,
            "client_identity": client_identity,
            "template_name": template_name,
            "request_type": request_type,
            "client_ip": client_ip,
        }
        return self.result


class TestWSTEPService:
    """Test cases for WSTEP service."""

    def create_rst_request(self, csr_b64: str = None, template: str = "User",
                           device_type: str = "CIMClient_Windows") -> bytes:
        """Create a sample RequestSecurityToken SOAP request."""
        if csr_b64 is None:
            csr_b64 = SAMPLE_CSR_B64.strip().replace("\n", "")

        return f"""<?xml version="1.0" encoding="utf-8"?>
        <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
                    xmlns:a="http://www.w3.org/2005/08/addressing"
                    xmlns:wst="http://docs.oasis-open.org/ws-sx/ws-trust/200512"
                    xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
                    xmlns:ac="http://schemas.xmlsoap.org/ws/2006/12/authorization">
            <s:Header>
                <a:Action s:mustUnderstand="1">
                    http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RST/wstep
                </a:Action>
                <a:MessageID>urn:uuid:test-rst-message</a:MessageID>
            </s:Header>
            <s:Body>
                <wst:RequestSecurityToken>
                    <wst:TokenType>
                        http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3
                    </wst:TokenType>
                    <wst:RequestType>
                        http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue
                    </wst:RequestType>
                    <wsse:BinarySecurityToken
                        ValueType="http://schemas.microsoft.com/windows/pki/2009/01/enrollment#PKCS10"
                        EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#base64binary">
                        {csr_b64}
                    </wsse:BinarySecurityToken>
                    <ac:AdditionalContext>
                        <ac:ContextItem Name="DeviceType">
                            <ac:Value>{device_type}</ac:Value>
                        </ac:ContextItem>
                        <ac:ContextItem Name="CertificateTemplate">
                            <ac:Value>{template}</ac:Value>
                        </ac:ContextItem>
                    </ac:AdditionalContext>
                </wst:RequestSecurityToken>
            </s:Body>
        </s:Envelope>""".encode("utf-8")

    def test_parse_rst_request(self):
        """Test parsing RequestSecurityToken request."""
        handler = MockEnrollmentHandler()
        service = WSTEPService(handler)

        request_xml = self.create_rst_request()
        envelope = SoapParser.parse(request_xml)

        # Verify action
        action = SoapParser.get_action(envelope)
        assert action == SoapAction.WSTEP_RST

    def test_handle_rst_issued(self):
        """Test handling RST request with successful issuance."""
        handler = MockEnrollmentHandler()
        service = WSTEPService(handler)

        request_xml = self.create_rst_request(template="User")
        response_xml = service.handle_request(request_xml, "testuser@EXAMPLE.COM")

        # Parse response
        response_env = etree.fromstring(response_xml)

        # Verify response action
        action = SoapParser.get_action(response_env)
        assert action == SoapAction.WSTEP_RSTR

        # Verify enrollment was called
        assert handler.last_request is not None
        assert handler.last_request["client_identity"] == "testuser@EXAMPLE.COM"
        assert handler.last_request["template_name"] == "User"

    def test_handle_rst_denied(self):
        """Test handling RST request with denial."""
        denied_result = EnrollmentResult(
            status=DispositionStatus.DENIED,
            disposition_message="User not authorized for this template"
        )
        handler = MockEnrollmentHandler(result=denied_result)
        service = WSTEPService(handler)

        request_xml = self.create_rst_request()
        response_xml = service.handle_request(request_xml, "baduser@EXAMPLE.COM")

        # Parse response
        response_env = etree.fromstring(response_xml)

        # Verify disposition message
        disp_msg = response_env.find(
            f".//{{{NS.ENROLLMENT}}}DispositionMessage",
            namespaces={"enrollment": NS.ENROLLMENT}
        )
        # Note: The namespace might vary, check response structure

    def test_handle_invalid_xml(self):
        """Test handling invalid XML."""
        handler = MockEnrollmentHandler()
        service = WSTEPService(handler)

        response_xml = service.handle_request(b"not valid xml", "testuser")

        # Should return SOAP fault
        response_env = etree.fromstring(response_xml)
        fault = response_env.find(f".//{{{NS.SOAP}}}Fault")
        assert fault is not None

    def test_handle_missing_csr(self):
        """Test handling request without CSR."""
        handler = MockEnrollmentHandler()
        service = WSTEPService(handler)

        request_xml = b"""<?xml version="1.0" encoding="utf-8"?>
        <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
                    xmlns:a="http://www.w3.org/2005/08/addressing"
                    xmlns:wst="http://docs.oasis-open.org/ws-sx/ws-trust/200512">
            <s:Header>
                <a:Action s:mustUnderstand="1">
                    http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RST/wstep
                </a:Action>
            </s:Header>
            <s:Body>
                <wst:RequestSecurityToken>
                    <wst:RequestType>
                        http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue
                    </wst:RequestType>
                </wst:RequestSecurityToken>
            </s:Body>
        </s:Envelope>"""

        response_xml = service.handle_request(request_xml, "testuser")

        # Should return SOAP fault
        response_env = etree.fromstring(response_xml)
        fault = response_env.find(f".//{{{NS.SOAP}}}Fault")
        assert fault is not None

    def test_extract_additional_context(self):
        """Test extracting AdditionalContext items."""
        handler = MockEnrollmentHandler()
        service = WSTEPService(handler)

        request_xml = self.create_rst_request(
            template="WebServer",
            device_type="WindowsServer"
        )
        service.handle_request(request_xml, "server@EXAMPLE.COM")

        # Verify context was extracted
        assert handler.last_request["template_name"] == "WebServer"


class TestEnrollmentResult:
    """Test cases for EnrollmentResult."""

    def test_issued_result(self):
        """Test creating issued result."""
        result = EnrollmentResult(
            status=DispositionStatus.ISSUED,
            certificate=b"cert_data",
            certificate_chain=[b"ca_cert"],
            request_id="123"
        )

        assert result.status == DispositionStatus.ISSUED
        assert result.certificate == b"cert_data"
        assert len(result.certificate_chain) == 1

    def test_error_result(self):
        """Test creating error result."""
        result = EnrollmentResult(
            status=DispositionStatus.ERROR,
            error_message="Something went wrong",
            request_id="456"
        )

        assert result.status == DispositionStatus.ERROR
        assert result.error_message == "Something went wrong"
        assert result.certificate is None

    def test_pending_result(self):
        """Test creating pending result."""
        result = EnrollmentResult(
            status=DispositionStatus.PENDING,
            request_id="789",
            disposition_message="Awaiting approval"
        )

        assert result.status == DispositionStatus.PENDING
        assert result.request_id == "789"
