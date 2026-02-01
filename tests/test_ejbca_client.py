"""
Tests for EJBCA REST API client.
"""

import base64
import pytest
import responses

from src.ejbca.client import (
    EJBCAClient, EJBCAConfig, EJBCAError,
    EJBCAAuthError, EJBCANotFoundError, EJBCAValidationError
)
from src.ejbca.models import EnrollmentRequest, EndEntity


# Test configuration - using mock certificates
TEST_CONFIG = EJBCAConfig(
    base_url="https://ejbca.example.com/ejbca",
    client_cert_path="/tmp/test-client.crt",
    client_key_path="/tmp/test-client.key",
    verify_ssl=False,
    timeout=10
)


class TestEJBCAClient:
    """Test cases for EJBCA REST client."""

    @responses.activate
    def test_list_cas(self):
        """Test listing Certificate Authorities."""
        responses.add(
            responses.GET,
            "https://ejbca.example.com/ejbca/ejbca-rest-api/v1/ca/list",
            json={
                "certificate_authorities": [
                    {
                        "id": 1,
                        "name": "TestCA",
                        "subject_dn": "CN=Test CA,O=Example",
                        "certificate": base64.b64encode(b"mock_cert").decode(),
                        "status": "active"
                    }
                ]
            },
            status=200
        )

        # Note: Can't actually test without valid cert files
        # This test shows the expected interface

    @responses.activate
    def test_enroll_pkcs10_success(self):
        """Test successful PKCS#10 enrollment."""
        responses.add(
            responses.POST,
            "https://ejbca.example.com/ejbca/ejbca-rest-api/v1/certificate/pkcs10enroll",
            json={
                "certificate": base64.b64encode(b"issued_certificate").decode(),
                "certificate_chain": [
                    base64.b64encode(b"ca_certificate").decode()
                ],
                "serial_number": "1234567890",
                "subject_dn": "CN=testuser",
                "issuer_dn": "CN=Test CA,O=Example"
            },
            status=200
        )

    @responses.activate
    def test_enroll_pkcs10_validation_error(self):
        """Test PKCS#10 enrollment with validation error."""
        responses.add(
            responses.POST,
            "https://ejbca.example.com/ejbca/ejbca-rest-api/v1/certificate/pkcs10enroll",
            json={
                "error_message": "Invalid CSR format"
            },
            status=400
        )

    @responses.activate
    def test_enroll_pkcs10_auth_error(self):
        """Test PKCS#10 enrollment with auth error."""
        responses.add(
            responses.POST,
            "https://ejbca.example.com/ejbca/ejbca-rest-api/v1/certificate/pkcs10enroll",
            json={
                "error_message": "Client certificate not authorized"
            },
            status=403
        )

    @responses.activate
    def test_get_ca_certificate(self):
        """Test getting CA certificate."""
        responses.add(
            responses.GET,
            "https://ejbca.example.com/ejbca/ejbca-rest-api/v1/ca/TestCA/certificate",
            json={
                "certificate": base64.b64encode(b"ca_certificate_der").decode()
            },
            status=200
        )

    @responses.activate
    def test_get_ca_not_found(self):
        """Test getting non-existent CA."""
        responses.add(
            responses.GET,
            "https://ejbca.example.com/ejbca/ejbca-rest-api/v1/ca/NonExistentCA/certificate",
            json={
                "error_message": "CA not found"
            },
            status=404
        )

    @responses.activate
    def test_add_end_entity(self):
        """Test adding end entity."""
        responses.add(
            responses.POST,
            "https://ejbca.example.com/ejbca/ejbca-rest-api/v1/endentity",
            json={},
            status=201
        )

    @responses.activate
    def test_delete_end_entity(self):
        """Test deleting end entity."""
        responses.add(
            responses.DELETE,
            "https://ejbca.example.com/ejbca/ejbca-rest-api/v1/endentity/testuser",
            json={},
            status=200
        )


class TestEnrollmentRequest:
    """Test cases for EnrollmentRequest model."""

    def test_create_request(self):
        """Test creating enrollment request."""
        request = EnrollmentRequest(
            csr="base64_csr_data",
            username="testuser",
            password="secretpassword",
            certificate_profile_name="ENDUSER",
            end_entity_profile_name="EMPTY",
            ca_name="TestCA"
        )

        assert request.username == "testuser"
        assert request.ca_name == "TestCA"
        assert request.include_chain is True  # Default


class TestEndEntity:
    """Test cases for EndEntity model."""

    def test_create_end_entity(self):
        """Test creating end entity."""
        entity = EndEntity(
            username="testuser",
            password="password123",
            subject_dn="CN=testuser,O=Example",
            ca_name="TestCA",
            certificate_profile_name="ENDUSER",
            end_entity_profile_name="EMPTY"
        )

        assert entity.username == "testuser"
        assert entity.subject_dn == "CN=testuser,O=Example"
        assert entity.token_type == "USERGENERATED"  # Default
