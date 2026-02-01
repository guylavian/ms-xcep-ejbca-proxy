"""
Conformance tests for MS-XCEP GetPoliciesResponse.

These tests validate that the XML output conforms to Microsoft's
MS-XCEP specification and will be accepted by Windows clients.

Reference: [MS-XCEP] X.509 Certificate Enrollment Policy Protocol
https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xcep/
"""

import pytest
from lxml import etree

from src.soap.xcep_service import XCEPService
from src.soap.types import (
    NS, SoapAction, CertificatePolicy, PolicyResponse, OID, CAInfo,
    CertificateValidity, PrivateKeyAttributes
)

from tests.xml_helpers import (
    XCEPValidator, validate_soap_envelope, validate_wsa_headers,
    validate_ca_uri_format, canonicalize_xml, compare_xml_structure
)


class MockPolicyProvider:
    """Mock policy provider that returns configurable policies."""

    def __init__(self, policies: PolicyResponse = None):
        self.policies = policies or self._create_default_policies()

    def _create_default_policies(self) -> PolicyResponse:
        """Create realistic test policies.

        OID Reference Logic:
        - Each OID has a unique reference_id (oIDReferenceID in XML)
        - Policy.policy_oid points to the OID's reference_id
        - The reference_id MUST be unique across all OIDs in the response
        """
        # OIDs with unique reference_ids
        oids = [
            OID(oid="2.16.840.1.101.3.4.2.1", name="SHA256", group=1, reference_id=0, default_name="SHA256"),
            OID(oid="1.2.840.113549.1.1.1", name="RSA", group=2, reference_id=1, default_name="RSA"),
            OID(oid="1.3.6.1.4.1.311.21.8.1", name="User", group=0, reference_id=2, default_name="User"),
            OID(oid="1.3.6.1.4.1.311.21.8.2", name="Computer", group=0, reference_id=3, default_name="Computer"),
        ]

        return PolicyResponse(
            policy_id="TestCA-Policy",
            policy_friendly_name="Test CA Certificate Policy",
            policies=[
                CertificatePolicy(
                    policy_oid="2",  # References OID with reference_id=2 (User template OID)
                    common_name="User",
                    certificate_validity=CertificateValidity(
                        validity_period_seconds=31536000,  # 1 year
                        renewal_period_seconds=5184000     # 60 days
                    ),
                    permission_enroll=True,
                    permission_auto_enroll=True,
                    private_key_attributes=PrivateKeyAttributes(
                        min_key_length=2048,
                        key_spec=1,
                        algorithm_oid="1.2.840.113549.1.1.1"
                    ),
                    hash_algorithm_oid="2.16.840.1.101.3.4.2.1"
                ),
                CertificatePolicy(
                    policy_oid="3",  # References OID with reference_id=3 (Computer template OID)
                    common_name="Computer",
                    certificate_validity=CertificateValidity(
                        validity_period_seconds=63072000,  # 2 years
                        renewal_period_seconds=7776000     # 90 days
                    ),
                    permission_enroll=True,
                    permission_auto_enroll=False,
                    private_key_attributes=PrivateKeyAttributes(
                        min_key_length=4096,
                        key_spec=1,
                        algorithm_oid="1.2.840.113549.1.1.1"
                    ),
                    hash_algorithm_oid="2.16.840.1.101.3.4.2.1"
                )
            ],
            cas=[
                CAInfo(
                    ca_reference=0,
                    ca_uri="https://proxy.example.com/ADPolicyProvider_CES_Kerberos/service.svc/CES",
                    certificate=b"mock_ca_certificate_der_data",
                    renewal_only=False
                )
            ],
            oids=oids
        )

    def get_policies_for_client(self, client_identity: str) -> tuple:
        return self.policies, "test_hash"

    def get_groups_hash(self, client_identity: str) -> str:
        return "test_hash"


def create_get_policies_request() -> bytes:
    """Create a valid GetPolicies SOAP request."""
    return b"""<?xml version="1.0" encoding="utf-8"?>
    <s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
                xmlns:a="http://www.w3.org/2005/08/addressing"
                xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
        <s:Header>
            <a:Action s:mustUnderstand="1">
                http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy/IPolicy/GetPolicies
            </a:Action>
            <a:MessageID>urn:uuid:test-message-id-12345</a:MessageID>
            <a:ReplyTo>
                <a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
            </a:ReplyTo>
            <a:To s:mustUnderstand="1">https://proxy.example.com/CEP</a:To>
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


class TestXCEPStructure:
    """Test XCEP response structure conformance."""

    @pytest.fixture
    def service(self):
        """Create XCEP service with mock provider."""
        return XCEPService(MockPolicyProvider())

    @pytest.fixture
    def response_xml(self, service) -> bytes:
        """Generate response XML."""
        request = create_get_policies_request()
        result = service.handle_request(request, "testuser@EXAMPLE.COM")
        return result[0] if isinstance(result, tuple) else result

    def test_soap_envelope_valid(self, response_xml):
        """Test that response is valid SOAP 1.2 envelope."""
        is_valid, errors = validate_soap_envelope(response_xml)
        assert is_valid, f"SOAP envelope invalid: {errors}"

    def test_wsa_action_correct(self, response_xml):
        """Test that WS-Addressing Action is correct."""
        is_valid, errors = validate_wsa_headers(
            response_xml,
            expected_action=SoapAction.XCEP_GET_POLICIES_RESPONSE
        )
        assert is_valid, f"WS-Addressing invalid: {errors}"

    def test_response_has_required_elements(self, response_xml):
        """Test that response contains all required MS-XCEP elements."""
        validator = XCEPValidator(response_xml)
        is_valid, errors, warnings = validator.validate_all()

        # Print warnings for visibility
        for warning in warnings:
            print(f"WARNING: {warning}")

        assert is_valid, f"XCEP validation failed: {errors}"

    def test_response_namespaces(self, response_xml):
        """Test that response uses correct namespaces."""
        tree = etree.fromstring(response_xml)

        # Must have SOAP 1.2 namespace
        assert tree.tag == f"{{{NS.SOAP}}}Envelope", \
            f"Expected SOAP 1.2 envelope, got {tree.tag}"

        # Find XCEP elements - should use correct namespace
        gpr = tree.find(f".//{{{NS.XCEP}}}GetPoliciesResponse")
        assert gpr is not None, "GetPoliciesResponse not found with correct namespace"


class TestXCEPOIDReferences:
    """Test OID reference integrity in XCEP responses."""

    @pytest.fixture
    def validator(self) -> XCEPValidator:
        """Create validator with response."""
        service = XCEPService(MockPolicyProvider())
        request = create_get_policies_request()
        result = service.handle_request(request, "testuser@EXAMPLE.COM")
        response_xml = result[0] if isinstance(result, tuple) else result
        return XCEPValidator(response_xml)

    def test_no_duplicate_oid_references(self, validator):
        """Test that OID reference IDs are unique."""
        is_valid, errors, _ = validator.validate_all()
        duplicate_errors = [e for e in errors if "Duplicate" in e]
        assert not duplicate_errors, f"Duplicate OIDs found: {duplicate_errors}"

    def test_policy_oid_references_exist(self, validator):
        """Test that all policy OID references point to existing OIDs."""
        is_valid, errors, _ = validator.validate_all()
        ref_errors = [e for e in errors if "non-existent OID" in e]
        assert not ref_errors, f"Invalid OID references: {ref_errors}"

    def test_oid_map_complete(self, validator):
        """Test that OID map contains expected entries."""
        oid_map = validator.get_oid_map()
        assert len(oid_map) > 0, "OID map is empty"

        # Should have SHA256 OID
        sha256_oid = "2.16.840.1.101.3.4.2.1"
        assert sha256_oid in oid_map.values(), f"SHA256 OID not found in map: {oid_map}"


class TestXCEPCAReferences:
    """Test CA reference integrity in XCEP responses."""

    @pytest.fixture
    def validator(self) -> XCEPValidator:
        """Create validator with response."""
        service = XCEPService(MockPolicyProvider())
        request = create_get_policies_request()
        result = service.handle_request(request, "testuser@EXAMPLE.COM")
        response_xml = result[0] if isinstance(result, tuple) else result
        return XCEPValidator(response_xml)

    def test_ca_references_valid(self, validator):
        """Test that policy CA references point to existing CAs."""
        is_valid, errors, _ = validator.validate_all()
        ca_errors = [e for e in errors if "non-existent CA" in e]
        assert not ca_errors, f"Invalid CA references: {ca_errors}"

    def test_ca_uri_format(self, validator):
        """Test that CA URIs are in correct format for Windows."""
        uris = validator.get_ca_uris()
        assert len(uris) > 0, "No CA URIs found"

        for uri in uris:
            is_valid, errors = validate_ca_uri_format(uri)
            assert is_valid, f"CA URI format invalid: {uri} - {errors}"

    def test_ca_uri_no_0000(self, validator):
        """Test that CA URIs don't contain 0.0.0.0."""
        uris = validator.get_ca_uris()
        for uri in uris:
            assert "0.0.0.0" not in uri, f"CA URI contains 0.0.0.0: {uri}"


class TestXCEPPolicyAttributes:
    """Test policy attribute validity."""

    @pytest.fixture
    def response_xml(self) -> bytes:
        """Generate response XML."""
        service = XCEPService(MockPolicyProvider())
        request = create_get_policies_request()
        result = service.handle_request(request, "testuser@EXAMPLE.COM")
        return result[0] if isinstance(result, tuple) else result

    def test_validity_periods_positive(self, response_xml):
        """Test that validity periods are positive integers."""
        tree = etree.fromstring(response_xml)

        for vp in tree.findall(f".//{{{NS.XCEP}}}validityPeriodSeconds"):
            if vp.text:
                value = int(vp.text)
                assert value > 0, f"validityPeriodSeconds must be positive: {value}"

        for rp in tree.findall(f".//{{{NS.XCEP}}}renewalPeriodSeconds"):
            if rp.text:
                value = int(rp.text)
                assert value > 0, f"renewalPeriodSeconds must be positive: {value}"

    def test_renewal_less_than_validity(self, response_xml):
        """Test that renewal period is less than validity period."""
        tree = etree.fromstring(response_xml)

        for validity in tree.findall(f".//{{{NS.XCEP}}}certificateValidity"):
            vp = validity.find(f"{{{NS.XCEP}}}validityPeriodSeconds")
            rp = validity.find(f"{{{NS.XCEP}}}renewalPeriodSeconds")

            if vp is not None and rp is not None and vp.text and rp.text:
                validity_secs = int(vp.text)
                renewal_secs = int(rp.text)
                assert renewal_secs < validity_secs, \
                    f"Renewal period ({renewal_secs}) should be < validity ({validity_secs})"

    def test_min_key_length_reasonable(self, response_xml):
        """Test that minimum key lengths are reasonable."""
        tree = etree.fromstring(response_xml)

        for mkl in tree.findall(f".//{{{NS.XCEP}}}minimalKeyLength"):
            if mkl.text:
                value = int(mkl.text)
                assert value >= 1024, f"Key length too small: {value}"
                assert value <= 16384, f"Key length too large: {value}"


class TestXCEPCanonical:
    """Test XML canonicalization and comparison."""

    @pytest.fixture
    def response_xml(self) -> bytes:
        """Generate response XML."""
        service = XCEPService(MockPolicyProvider())
        request = create_get_policies_request()
        result = service.handle_request(request, "testuser@EXAMPLE.COM")
        return result[0] if isinstance(result, tuple) else result

    def test_response_canonicalizes(self, response_xml):
        """Test that response can be canonicalized."""
        canonical = canonicalize_xml(response_xml)
        assert len(canonical) > 0, "Canonicalized XML is empty"

    def test_response_idempotent(self, response_xml):
        """Test that same request produces structurally identical response."""
        service = XCEPService(MockPolicyProvider())
        request = create_get_policies_request()

        result1 = service.handle_request(request, "testuser@EXAMPLE.COM")
        result2 = service.handle_request(request, "testuser@EXAMPLE.COM")

        xml1 = result1[0] if isinstance(result1, tuple) else result1
        xml2 = result2[0] if isinstance(result2, tuple) else result2

        # Compare structure (ignoring timestamps/IDs)
        is_equal, differences = compare_xml_structure(
            canonicalize_xml(xml1),
            canonicalize_xml(xml2),
            ignore_values=False
        )

        assert is_equal, f"Responses differ: {differences}"


class TestXCEPEdgeCases:
    """Test edge cases and error handling."""

    def test_empty_policies(self):
        """Test response with no policies."""
        empty_policies = PolicyResponse(
            policy_id="Empty-Policy",
            policy_friendly_name="Empty Policy",
            policies=[],
            cas=[],
            oids=[]
        )

        provider = MockPolicyProvider(empty_policies)
        service = XCEPService(provider)

        request = create_get_policies_request()
        result = service.handle_request(request, "testuser@EXAMPLE.COM")
        response_xml = result[0] if isinstance(result, tuple) else result

        # Should still be valid SOAP
        is_valid, errors = validate_soap_envelope(response_xml)
        assert is_valid, f"Empty policy response invalid: {errors}"

    def test_special_characters_in_names(self):
        """Test handling of special characters in policy names."""
        policies = PolicyResponse(
            policy_id="Test<>&Policy",
            policy_friendly_name="Test & Special <Characters>",
            policies=[],
            cas=[],
            oids=[]
        )

        provider = MockPolicyProvider(policies)
        service = XCEPService(provider)

        request = create_get_policies_request()
        result = service.handle_request(request, "testuser@EXAMPLE.COM")
        response_xml = result[0] if isinstance(result, tuple) else result

        # Should be parseable (special chars escaped)
        tree = etree.fromstring(response_xml)
        assert tree is not None

    def test_unicode_in_names(self):
        """Test handling of Unicode in policy names."""
        policies = PolicyResponse(
            policy_id="מדיניות-תעודות",
            policy_friendly_name="Certificate Policy מדיניות",
            policies=[],
            cas=[],
            oids=[]
        )

        provider = MockPolicyProvider(policies)
        service = XCEPService(provider)

        request = create_get_policies_request()
        result = service.handle_request(request, "testuser@EXAMPLE.COM")
        response_xml = result[0] if isinstance(result, tuple) else result

        # Should be parseable
        tree = etree.fromstring(response_xml)
        assert tree is not None
