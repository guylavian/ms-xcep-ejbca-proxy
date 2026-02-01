"""
Tests for MS-XCEP service.
"""

import pytest
from lxml import etree

from src.soap.xcep_service import XCEPService, GetPoliciesRequest
from src.soap.types import (
    NS, SoapAction, SoapParser, SoapBuilder,
    CertificatePolicy, PolicyResponse, OID, CAInfo,
    CertificateValidity, PrivateKeyAttributes
)
from src.ad.templates import TemplateManager, TemplateMappingConfig, PolicyProvider


class MockPolicyProvider:
    """Mock policy provider for testing."""

    def __init__(self, policies=None):
        self.policies = policies or self._create_default_policies()

    def _create_default_policies(self) -> PolicyResponse:
        return PolicyResponse(
            policy_id="TestCA-Policy",
            policy_friendly_name="Test CA Certificate Policy",
            policies=[
                CertificatePolicy(
                    policy_oid="0",
                    certificate_validity=CertificateValidity(
                        validity_period_seconds=31536000,
                        renewal_period_seconds=5184000
                    ),
                    permission_enroll=True,
                    permission_auto_enroll=True,
                    private_key_attributes=PrivateKeyAttributes(min_key_length=2048)
                )
            ],
            cas=[
                CAInfo(
                    ca_reference=0,
                    ca_uri="https://proxy.example.com/CES",
                    certificate=b"mock_ca_cert",
                    renewal_only=False
                )
            ],
            oids=[
                OID(oid="2.16.840.1.101.3.4.2.1", name="SHA256", group=0),
                OID(oid="1.2.840.113549.1.1.1", name="RSA", group=1),
            ]
        )

    def get_policies_for_client(self, client_identity: str) -> tuple:
        """Return policies and groups_hash."""
        return self.policies, "test_groups_hash"
    
    def get_groups_hash(self, client_identity: str) -> str:
        """Return groups hash for caching."""
        return "test_groups_hash"


class TestXCEPService:
    """Test cases for XCEP service."""

    def test_parse_get_policies_request(self):
        """Test parsing GetPolicies SOAP request."""
        request_xml = b"""<?xml version="1.0" encoding="utf-8"?>
        <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
                    xmlns:a="http://www.w3.org/2005/08/addressing">
            <s:Header>
                <a:Action s:mustUnderstand="1">
                    http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy/IPolicy/GetPolicies
                </a:Action>
                <a:MessageID>urn:uuid:12345678-1234-1234-1234-123456789012</a:MessageID>
            </s:Header>
            <s:Body xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                <GetPolicies xmlns="http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy">
                    <client>
                        <lastUpdate>0001-01-01T00:00:00</lastUpdate>
                        <preferredLanguage xsi:nil="true"/>
                    </client>
                    <requestFilter xsi:nil="true"/>
                </GetPolicies>
            </s:Body>
        </s:Envelope>"""

        envelope = SoapParser.parse(request_xml)

        # Verify action
        action = SoapParser.get_action(envelope)
        assert action == SoapAction.XCEP_GET_POLICIES

        # Verify message ID
        msg_id = SoapParser.get_message_id(envelope)
        assert msg_id == "urn:uuid:12345678-1234-1234-1234-123456789012"

    def test_handle_get_policies(self):
        """Test handling GetPolicies request."""
        provider = MockPolicyProvider()
        service = XCEPService(provider)

        request_xml = b"""<?xml version="1.0" encoding="utf-8"?>
        <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
                    xmlns:a="http://www.w3.org/2005/08/addressing">
            <s:Header>
                <a:Action s:mustUnderstand="1">
                    http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy/IPolicy/GetPolicies
                </a:Action>
                <a:MessageID>urn:uuid:test-message-id</a:MessageID>
            </s:Header>
            <s:Body xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
                <GetPolicies xmlns="http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy">
                    <client>
                        <lastUpdate xsi:nil="true"/>
                        <preferredLanguage xsi:nil="true"/>
                    </client>
                    <requestFilter xsi:nil="true"/>
                </GetPolicies>
            </s:Body>
        </s:Envelope>"""

        result = service.handle_request(request_xml, "testuser@EXAMPLE.COM")
        # handle_request returns (xml_bytes, groups_hash) tuple
        response_xml = result[0] if isinstance(result, tuple) else result

        # Parse response
        response_env = etree.fromstring(response_xml)

        # Verify response action
        action = SoapParser.get_action(response_env)
        assert action == SoapAction.XCEP_GET_POLICIES_RESPONSE

        # Verify response contains GetPoliciesResponse
        gpr = response_env.find(f".//{{{NS.XCEP}}}GetPoliciesResponse")
        assert gpr is not None

        # Verify policyID
        policy_id = response_env.find(f".//{{{NS.XCEP}}}policyID")
        assert policy_id is not None
        assert policy_id.text == "TestCA-Policy"

    def test_handle_invalid_xml(self):
        """Test handling invalid XML request."""
        provider = MockPolicyProvider()
        service = XCEPService(provider)

        result = service.handle_request(b"not valid xml", "testuser")
        response_xml = result[0] if isinstance(result, tuple) else result

        # Should return SOAP fault
        response_env = etree.fromstring(response_xml)
        fault = response_env.find(f".//{{{NS.SOAP}}}Fault")
        assert fault is not None

    def test_handle_unknown_action(self):
        """Test handling unknown SOAP action."""
        provider = MockPolicyProvider()
        service = XCEPService(provider)

        request_xml = b"""<?xml version="1.0" encoding="utf-8"?>
        <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
                    xmlns:a="http://www.w3.org/2005/08/addressing">
            <s:Header>
                <a:Action s:mustUnderstand="1">
                    http://unknown.action/
                </a:Action>
            </s:Header>
            <s:Body/>
        </s:Envelope>"""

        result = service.handle_request(request_xml, "testuser")
        response_xml = result[0] if isinstance(result, tuple) else result

        # Should return SOAP fault
        response_env = etree.fromstring(response_xml)
        fault = response_env.find(f".//{{{NS.SOAP}}}Fault")
        assert fault is not None


class TestSoapBuilder:
    """Test cases for SOAP message building."""

    def test_create_envelope(self):
        """Test creating SOAP envelope."""
        envelope = SoapBuilder.create_envelope()

        assert envelope.tag == f"{{{NS.SOAP}}}Envelope"
        assert envelope.nsmap.get("s") == NS.SOAP

    def test_add_header(self):
        """Test adding SOAP header."""
        envelope = SoapBuilder.create_envelope()
        header = SoapBuilder.add_header(
            envelope,
            action=SoapAction.XCEP_GET_POLICIES_RESPONSE,
            relates_to="urn:uuid:test"
        )

        # Verify action
        action = header.find(f"{{{NS.WSA}}}Action")
        assert action is not None
        assert action.text == SoapAction.XCEP_GET_POLICIES_RESPONSE

        # Verify RelatesTo
        relates = header.find(f"{{{NS.WSA}}}RelatesTo")
        assert relates is not None
        assert relates.text == "urn:uuid:test"

    def test_create_soap_fault(self):
        """Test creating SOAP fault."""
        fault_env = SoapBuilder.create_soap_fault(
            code="Sender",
            reason="Test error",
            detail="Detailed error message"
        )

        fault = fault_env.find(f".//{{{NS.SOAP}}}Fault")
        assert fault is not None

        reason = fault_env.find(f".//{{{NS.SOAP}}}Reason/{{{NS.SOAP}}}Text")
        assert reason is not None
        assert reason.text == "Test error"


class TestSoapParser:
    """Test cases for SOAP message parsing."""

    def test_parse_valid_xml(self):
        """Test parsing valid SOAP XML."""
        xml = b"""<?xml version="1.0"?>
        <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
            <s:Header/>
            <s:Body/>
        </s:Envelope>"""

        envelope = SoapParser.parse(xml)
        assert envelope is not None
        assert envelope.tag == f"{{{NS.SOAP}}}Envelope"

    def test_get_body(self):
        """Test extracting SOAP body."""
        xml = b"""<?xml version="1.0"?>
        <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">
            <s:Header/>
            <s:Body>
                <TestElement>content</TestElement>
            </s:Body>
        </s:Envelope>"""

        envelope = SoapParser.parse(xml)
        body = SoapParser.get_body(envelope)

        assert body is not None
        assert len(body) == 1  # One child element
