"""
Conformance tests for MS-WSTEP RequestSecurityTokenResponse.

These tests validate that the XML output conforms to Microsoft's
MS-WSTEP specification and will be accepted by Windows clients.

Reference: [MS-WSTEP] WS-Trust X.509v3 Token Enrollment Extensions
"""

import base64
import pytest
from datetime import datetime, timedelta, timezone
from lxml import etree

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding

from src.soap.wstep_service import WSTEPService, EnrollmentResult, DispositionStatus
from src.soap.types import NS, SoapAction

from tests.xml_helpers import (
    WSTEPValidator, validate_soap_envelope, validate_wsa_headers,
    canonicalize_xml
)


def create_test_certificate() -> bytes:
    """Create a self-signed test certificate in DER format."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Test User"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org"),
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .sign(private_key, hashes.SHA256())
    )

    return cert.public_bytes(encoding=Encoding.DER)


def create_test_ca_certificate() -> bytes:
    """Create a self-signed CA certificate in DER format."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Test CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test Org"),
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=3650))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=1),
            critical=True,
        )
        .sign(private_key, hashes.SHA256())
    )

    return cert.public_bytes(encoding=Encoding.DER)


# Pre-create certificates for tests
TEST_CERT_DER = create_test_certificate()
TEST_CA_CERT_DER = create_test_ca_certificate()


# Valid CSR for testing (base64 DER)
SAMPLE_CSR_B64 = "MIICWDCCAUACAQAwEzERMA8GA1UEAwwIVGVzdFVzZXIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDQdtxhQZ0H5aYiAgpWMkmbVvGjB/OMHCImK/NaXQfIYe9McAecy8Nc5O4TbdZYYAkPR4L8wEpPVxBmf1nG4TopmXFnNaxYbUH9XS4W1N09j/SXxIqKUl0vk3DfTlZX8J7CX/4fC70P2ht7af5KRRAmD1CGlJRhr7B45VRaPGDOWcCDyY8dfphBMGGEARTfStFAzWd631kvQSwV6Qqi+zNy+QzMuSaR9AmXmw90vIAbeFbs7vG4NEFNP3kNx9huUWzqq3ZHWLs5lc+6XDVlUwrDg5YtcuaZa3GHKy8C+rrF8YtECYIPMwnFd0Op94JD2+XKb8R8BM2xsH3c/m4LAKxTAgMBAAGgADANBgkqhkiG9w0BAQsFAAOCAQEAmy8JZSy9NaQ3E5gE0TZInwV0+AXvkIT3g9P/ItcLfuKOqcmUfbyTBbk74uT0LxWzvwgv44YtUecOgjJsK8yyGL0MgScxYXBGI1I5bO1V8wig9xO72BI7xiiWzZbJpyaEsRcxJG8trfoTTt4xeF1C85dwcPYQNGlieq/6r8HJ3TUjmkRxyV2d8lVZXRw4tuqGd2a2UlMCQjXKEFhMoYLjDhPdGWomDRnC6pYJUydwNlK1szQv4U7b+jUaWHq5znb92anZ/a+Pt0NQcPC7gvXmoRuPDve/kiZ9Z8JsZ1w6Z5tXZY4IflauOJMQbXNf0cIr0YBPUYNVFnISM4uYhIgYlA=="


class MockEnrollmentHandler:
    """Mock enrollment handler for testing."""

    def __init__(self, result: EnrollmentResult = None):
        self.last_request = None
        self.result = result or EnrollmentResult(
            status=DispositionStatus.ISSUED,
            certificate=TEST_CERT_DER,
            certificate_chain=[TEST_CA_CERT_DER],
            request_id="12345",
            disposition_message="Issued"
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


def create_rst_request(csr_b64: str = None, template: str = "User") -> bytes:
    """Create a valid RequestSecurityToken SOAP request."""
    if csr_b64 is None:
        csr_b64 = SAMPLE_CSR_B64

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
            <a:MessageID>urn:uuid:test-rst-message-12345</a:MessageID>
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
                    <ac:ContextItem Name="CertificateTemplate">
                        <ac:Value>{template}</ac:Value>
                    </ac:ContextItem>
                </ac:AdditionalContext>
            </wst:RequestSecurityToken>
        </s:Body>
    </s:Envelope>""".encode("utf-8")


class TestWSTEPStructure:
    """Test WSTEP response structure conformance."""

    @pytest.fixture
    def service(self):
        """Create WSTEP service with mock handler."""
        return WSTEPService(MockEnrollmentHandler())

    @pytest.fixture
    def response_xml(self, service) -> bytes:
        """Generate response XML."""
        request = create_rst_request()
        return service.handle_request(request, "testuser@EXAMPLE.COM", "127.0.0.1")

    def test_soap_envelope_valid(self, response_xml):
        """Test that response is valid SOAP 1.2 envelope."""
        is_valid, errors = validate_soap_envelope(response_xml)
        assert is_valid, f"SOAP envelope invalid: {errors}"

    def test_wsa_action_correct(self, response_xml):
        """Test that WS-Addressing Action is correct."""
        is_valid, errors = validate_wsa_headers(
            response_xml,
            expected_action=SoapAction.WSTEP_RSTR
        )
        assert is_valid, f"WS-Addressing invalid: {errors}"

    def test_response_has_required_elements(self, response_xml):
        """Test that response contains all required MS-WSTEP elements."""
        validator = WSTEPValidator(response_xml)
        is_valid, errors, warnings = validator.validate_all()

        for warning in warnings:
            print(f"WARNING: {warning}")

        assert is_valid, f"WSTEP validation failed: {errors}"

    def test_response_namespaces(self, response_xml):
        """Test that response uses correct namespaces."""
        tree = etree.fromstring(response_xml)

        # Must have SOAP 1.2 namespace
        assert tree.tag == f"{{{NS.SOAP}}}Envelope", \
            f"Expected SOAP 1.2 envelope, got {tree.tag}"

        # Find WST elements
        rstr = tree.find(f".//{{{NS.WST}}}RequestSecurityTokenResponse")
        assert rstr is not None, "RSTR not found with correct namespace"


class TestWSTEPPKCS7:
    """Test PKCS#7 certificate response."""

    @pytest.fixture
    def response_xml(self) -> bytes:
        """Generate response with certificate."""
        handler = MockEnrollmentHandler()
        service = WSTEPService(handler)
        request = create_rst_request()
        return service.handle_request(request, "testuser@EXAMPLE.COM", "127.0.0.1")

    def test_pkcs7_valid(self, response_xml):
        """Test that PKCS#7 is valid and parseable."""
        validator = WSTEPValidator(response_xml)
        is_valid, errors, _ = validator.validate_all()

        pkcs7_errors = [e for e in errors if "PKCS#7" in e]
        assert not pkcs7_errors, f"PKCS#7 errors: {pkcs7_errors}"

    def test_pkcs7_contains_certificate(self, response_xml):
        """Test that PKCS#7 contains at least one certificate."""
        validator = WSTEPValidator(response_xml)
        certs = validator.get_certificate_chain()

        assert len(certs) >= 1, "PKCS#7 should contain at least 1 certificate"

    def test_pkcs7_contains_chain(self, response_xml):
        """Test that PKCS#7 contains certificate chain."""
        validator = WSTEPValidator(response_xml)
        certs = validator.get_certificate_chain()

        # With our mock, we include end-entity + CA
        assert len(certs) >= 2, f"PKCS#7 should contain chain, got {len(certs)} certs"

    def test_pkcs7_first_cert_is_end_entity(self, response_xml):
        """Test that first certificate is end-entity (not CA)."""
        validator = WSTEPValidator(response_xml)
        certs = validator.get_certificate_chain()

        if len(certs) >= 1:
            first_cert = certs[0]
            # End-entity cert should have CA=False
            try:
                bc = first_cert.extensions.get_extension_for_oid(
                    x509.oid.ExtensionOID.BASIC_CONSTRAINTS
                )
                assert not bc.value.ca, "First certificate should not be a CA"
            except x509.ExtensionNotFound:
                pass  # No BasicConstraints is OK for end-entity


class TestWSTEPDispositions:
    """Test different enrollment dispositions."""

    def test_issued_response(self):
        """Test successful issuance response."""
        handler = MockEnrollmentHandler(EnrollmentResult(
            status=DispositionStatus.ISSUED,
            certificate=TEST_CERT_DER,
            certificate_chain=[TEST_CA_CERT_DER],
            request_id="12345",
            disposition_message="Issued"
        ))
        service = WSTEPService(handler)

        response_xml = service.handle_request(
            create_rst_request(),
            "testuser@EXAMPLE.COM",
            "127.0.0.1"
        )

        validator = WSTEPValidator(response_xml)
        is_valid, errors, _ = validator.validate_all()
        assert is_valid, f"Issued response invalid: {errors}"

        # Should have RequestedSecurityToken
        tree = etree.fromstring(response_xml)
        rst = tree.find(f".//{{{NS.WST}}}RequestedSecurityToken")
        assert rst is not None, "Issued response should have RequestedSecurityToken"

    def test_pending_response(self):
        """Test pending approval response."""
        handler = MockEnrollmentHandler(EnrollmentResult(
            status=DispositionStatus.PENDING,
            request_id="67890",
            disposition_message="Pending administrator approval"
        ))
        service = WSTEPService(handler)

        response_xml = service.handle_request(
            create_rst_request(),
            "testuser@EXAMPLE.COM",
            "127.0.0.1"
        )

        # Should be valid SOAP
        is_valid, errors = validate_soap_envelope(response_xml)
        assert is_valid, f"Pending response invalid: {errors}"

        # Should have disposition message
        tree = etree.fromstring(response_xml)
        disp = tree.find(f".//{{{NS.ENROLLMENT}}}DispositionMessage")
        assert disp is not None, "Pending response should have DispositionMessage"

    def test_denied_response(self):
        """Test denied enrollment response."""
        handler = MockEnrollmentHandler(EnrollmentResult(
            status=DispositionStatus.DENIED,
            request_id="99999",
            disposition_message="User not authorized for this template"
        ))
        service = WSTEPService(handler)

        response_xml = service.handle_request(
            create_rst_request(),
            "testuser@EXAMPLE.COM",
            "127.0.0.1"
        )

        # Should be valid SOAP
        is_valid, errors = validate_soap_envelope(response_xml)
        assert is_valid, f"Denied response invalid: {errors}"

    def test_error_response(self):
        """Test error response."""
        handler = MockEnrollmentHandler(EnrollmentResult(
            status=DispositionStatus.ERROR,
            error_message="CA unavailable",
            request_id="error-123"
        ))
        service = WSTEPService(handler)

        response_xml = service.handle_request(
            create_rst_request(),
            "testuser@EXAMPLE.COM",
            "127.0.0.1"
        )

        # Should be valid SOAP
        is_valid, errors = validate_soap_envelope(response_xml)
        assert is_valid, f"Error response invalid: {errors}"


class TestWSTEPRequestParsing:
    """Test parsing of incoming WSTEP requests."""

    def test_extracts_template_name(self):
        """Test that template name is extracted from request."""
        handler = MockEnrollmentHandler()
        service = WSTEPService(handler)

        service.handle_request(
            create_rst_request(template="WebServer"),
            "testuser@EXAMPLE.COM",
            "127.0.0.1"
        )

        assert handler.last_request is not None
        assert handler.last_request["template_name"] == "WebServer"

    def test_extracts_csr_data(self):
        """Test that CSR is extracted and decoded from request."""
        handler = MockEnrollmentHandler()
        service = WSTEPService(handler)

        service.handle_request(
            create_rst_request(),
            "testuser@EXAMPLE.COM",
            "127.0.0.1"
        )

        assert handler.last_request is not None
        assert handler.last_request["csr_data"] is not None
        assert len(handler.last_request["csr_data"]) > 0

    def test_handles_missing_template(self):
        """Test handling when template is not specified."""
        handler = MockEnrollmentHandler()
        service = WSTEPService(handler)

        # Request without CertificateTemplate context item
        request_xml = f"""<?xml version="1.0" encoding="utf-8"?>
        <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
                    xmlns:a="http://www.w3.org/2005/08/addressing"
                    xmlns:wst="http://docs.oasis-open.org/ws-sx/ws-trust/200512"
                    xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
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
                    <wsse:BinarySecurityToken
                        ValueType="http://schemas.microsoft.com/windows/pki/2009/01/enrollment#PKCS10">
                        {SAMPLE_CSR_B64}
                    </wsse:BinarySecurityToken>
                </wst:RequestSecurityToken>
            </s:Body>
        </s:Envelope>""".encode("utf-8")

        response = service.handle_request(request_xml, "testuser@EXAMPLE.COM", "127.0.0.1")

        # Should still work (use default template)
        is_valid, errors = validate_soap_envelope(response)
        assert is_valid


class TestWSTEPCanonical:
    """Test XML canonicalization."""

    def test_response_canonicalizes(self):
        """Test that response can be canonicalized."""
        handler = MockEnrollmentHandler()
        service = WSTEPService(handler)
        response_xml = service.handle_request(
            create_rst_request(),
            "testuser@EXAMPLE.COM",
            "127.0.0.1"
        )

        canonical = canonicalize_xml(response_xml)
        assert len(canonical) > 0


class TestWSTEPEdgeCases:
    """Test edge cases."""

    def test_invalid_base64_csr(self):
        """Test handling of invalid base64 in CSR."""
        handler = MockEnrollmentHandler()
        service = WSTEPService(handler)

        request_xml = b"""<?xml version="1.0" encoding="utf-8"?>
        <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
                    xmlns:a="http://www.w3.org/2005/08/addressing"
                    xmlns:wst="http://docs.oasis-open.org/ws-sx/ws-trust/200512"
                    xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
            <s:Header>
                <a:Action s:mustUnderstand="1">
                    http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RST/wstep
                </a:Action>
            </s:Header>
            <s:Body>
                <wst:RequestSecurityToken>
                    <wsse:BinarySecurityToken>
                        not-valid-base64!!!
                    </wsse:BinarySecurityToken>
                </wst:RequestSecurityToken>
            </s:Body>
        </s:Envelope>"""

        response = service.handle_request(request_xml, "testuser@EXAMPLE.COM", "127.0.0.1")

        # Should return SOAP fault
        tree = etree.fromstring(response)
        fault = tree.find(f".//{{{NS.SOAP}}}Fault")
        assert fault is not None, "Should return SOAP fault for invalid base64"

    def test_empty_csr(self):
        """Test handling of empty CSR."""
        handler = MockEnrollmentHandler()
        service = WSTEPService(handler)

        request_xml = b"""<?xml version="1.0" encoding="utf-8"?>
        <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
                    xmlns:a="http://www.w3.org/2005/08/addressing"
                    xmlns:wst="http://docs.oasis-open.org/ws-sx/ws-trust/200512"
                    xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
            <s:Header>
                <a:Action s:mustUnderstand="1">
                    http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RST/wstep
                </a:Action>
            </s:Header>
            <s:Body>
                <wst:RequestSecurityToken>
                    <wsse:BinarySecurityToken></wsse:BinarySecurityToken>
                </wst:RequestSecurityToken>
            </s:Body>
        </s:Envelope>"""

        response = service.handle_request(request_xml, "testuser@EXAMPLE.COM", "127.0.0.1")

        # Should return SOAP fault
        tree = etree.fromstring(response)
        fault = tree.find(f".//{{{NS.SOAP}}}Fault")
        assert fault is not None, "Should return SOAP fault for empty CSR"


# Add NS.ENROLLMENT if not defined
if not hasattr(NS, 'ENROLLMENT'):
    NS.ENROLLMENT = "http://schemas.microsoft.com/windows/pki/2009/01/enrollment"
