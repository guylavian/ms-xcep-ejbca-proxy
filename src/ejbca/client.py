"""
EJBCA REST API Client.

Communicates with EJBCA's REST API for certificate enrollment operations.
Uses mutual TLS (client certificate) authentication.

Reference: https://docs.keyfactor.com/ejbca/latest/ejbca-rest-interface
"""

import base64
import logging
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urljoin

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .models import (
    CAInfo, EndEntity,
    EnrollmentRequest, EnrollmentResponse
)

logger = logging.getLogger(__name__)


class EJBCAError(Exception):
    """Base exception for EJBCA API errors."""

    def __init__(self, message: str, status_code: int = None, error_code: str = None):
        super().__init__(message)
        self.status_code = status_code
        self.error_code = error_code


class EJBCAAuthError(EJBCAError):
    """Authentication/authorization error."""
    pass


class EJBCANotFoundError(EJBCAError):
    """Resource not found error."""
    pass


class EJBCAValidationError(EJBCAError):
    """Validation error (invalid CSR, profile, etc.)."""
    pass


@dataclass
class EJBCAConfig:
    """EJBCA connection configuration."""

    base_url: str  # e.g., "https://ejbca.example.com/ejbca"
    client_cert_path: str
    client_key_path: str
    ca_cert_path: Optional[str] = None  # CA certificate for server verification
    verify_ssl: bool = True
    timeout: int = 30
    max_retries: int = 3


class EJBCAClient:
    """
    EJBCA REST API client.

    Handles certificate enrollment, CA queries, and profile management.
    """

    # API endpoints
    ENDPOINT_PKCS10_ENROLL = "/ejbca-rest-api/v1/certificate/pkcs10enroll"
    ENDPOINT_CERTIFICATE = "/ejbca-rest-api/v1/certificate"
    ENDPOINT_CA = "/ejbca-rest-api/v1/ca"
    ENDPOINT_CA_LIST = "/ejbca-rest-api/v1/ca/list"
    ENDPOINT_CERT_PROFILE = "/ejbca-rest-api/v1/certificate/profile"
    ENDPOINT_EE_PROFILE = "/ejbca-rest-api/v1/endentity/profile"
    ENDPOINT_END_ENTITY = "/ejbca-rest-api/v1/endentity"

    def __init__(self, config: EJBCAConfig):
        """
        Initialize EJBCA client.

        Args:
            config: EJBCA connection configuration
        """
        self.config = config
        self.session = self._create_session()

    def _create_session(self) -> requests.Session:
        """Create requests session with retry logic and client cert."""
        session = requests.Session()

        # Configure client certificate authentication
        session.cert = (self.config.client_cert_path, self.config.client_key_path)

        # Configure SSL verification
        if self.config.ca_cert_path:
            session.verify = self.config.ca_cert_path
        else:
            session.verify = self.config.verify_ssl

        # Configure retries
        retry_strategy = Retry(
            total=self.config.max_retries,
            backoff_factor=0.5,
            status_forcelist=[500, 502, 503, 504],
            allowed_methods=["GET", "POST", "PUT"]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("https://", adapter)

        # Default headers
        session.headers.update({
            "Content-Type": "application/json",
            "Accept": "application/json"
        })

        return session

    def _url(self, endpoint: str) -> str:
        """Build full URL for endpoint."""
        return urljoin(self.config.base_url, endpoint)

    def _handle_response(self, response: requests.Response) -> dict:
        """Handle API response and raise appropriate exceptions."""
        try:
            data = response.json() if response.content else {}
        except ValueError:
            data = {"raw": response.text}

        if response.status_code == 200 or response.status_code == 201:
            return data
        elif response.status_code == 400:
            error_msg = data.get("error_message", data.get("message", "Bad request"))
            raise EJBCAValidationError(error_msg, response.status_code)
        elif response.status_code == 401 or response.status_code == 403:
            error_msg = data.get("error_message", "Authentication failed")
            raise EJBCAAuthError(error_msg, response.status_code)
        elif response.status_code == 404:
            error_msg = data.get("error_message", "Resource not found")
            raise EJBCANotFoundError(error_msg, response.status_code)
        else:
            error_msg = data.get("error_message", f"API error: {response.status_code}")
            raise EJBCAError(error_msg, response.status_code)

    # Certificate Operations

    def enroll_pkcs10(self, request: EnrollmentRequest) -> EnrollmentResponse:
        """
        Enroll certificate using PKCS#10 CSR.

        Args:
            request: Enrollment request with CSR and profile information

        Returns:
            EnrollmentResponse with issued certificate
        """
        payload = {
            "certificate_request": request.csr,
            "certificate_profile_name": request.certificate_profile_name,
            "end_entity_profile_name": request.end_entity_profile_name,
            "ca_name": request.ca_name,
            "username": request.username,
            "password": request.password,
            "include_chain": request.include_chain
        }

        logger.debug(f"PKCS#10 enrollment request for {request.username}")

        response = self.session.post(
            self._url(self.ENDPOINT_PKCS10_ENROLL),
            json=payload,
            timeout=self.config.timeout
        )

        data = self._handle_response(response)

        # Parse response
        cert_b64 = data.get("certificate", "")
        cert_der = base64.b64decode(cert_b64) if cert_b64 else b""

        chain = []
        for chain_cert_b64 in data.get("certificate_chain", []):
            chain.append(base64.b64decode(chain_cert_b64))

        return EnrollmentResponse(
            certificate=cert_der,
            certificate_chain=chain,
            serial_number=data.get("serial_number", ""),
            subject_dn=data.get("subject_dn", ""),
            issuer_dn=data.get("issuer_dn", "")
        )

    def get_certificate_by_serial(self, issuer_dn: str,
                                  serial_number: str) -> Optional[bytes]:
        """
        Get certificate by issuer DN and serial number.

        Returns:
            DER encoded certificate or None if not found
        """
        endpoint = f"{self.ENDPOINT_CERTIFICATE}/{issuer_dn}/{serial_number}"

        try:
            response = self.session.get(
                self._url(endpoint),
                timeout=self.config.timeout
            )
            data = self._handle_response(response)
            cert_b64 = data.get("certificate", "")
            return base64.b64decode(cert_b64) if cert_b64 else None
        except EJBCANotFoundError:
            return None

    def revoke_certificate(self, issuer_dn: str, serial_number: str,
                           reason: int = 0) -> bool:
        """
        Revoke a certificate.

        Args:
            issuer_dn: Issuer DN of the certificate
            serial_number: Serial number of the certificate
            reason: Revocation reason code (RFC 5280)

        Returns:
            True if revocation succeeded
        """
        endpoint = f"{self.ENDPOINT_CERTIFICATE}/{issuer_dn}/{serial_number}/revoke"
        params = {"reason": reason}

        response = self.session.put(
            self._url(endpoint),
            params=params,
            timeout=self.config.timeout
        )
        self._handle_response(response)
        return True

    # CA Operations

    def list_cas(self) -> list:
        """
        List all available Certificate Authorities.

        Returns:
            List of CAInfo objects
        """
        response = self.session.get(
            self._url(self.ENDPOINT_CA_LIST),
            timeout=self.config.timeout
        )
        data = self._handle_response(response)

        cas = []
        for ca_data in data.get("certificate_authorities", []):
            cas.append(CAInfo(
                ca_id=ca_data.get("id", 0),
                ca_name=ca_data.get("name", ""),
                subject_dn=ca_data.get("subject_dn", ""),
                certificate=base64.b64decode(ca_data.get("certificate", "")),
                status=ca_data.get("status", "active")
            ))

        return cas

    def get_ca(self, ca_name: str) -> Optional[CAInfo]:
        """
        Get CA information by name.

        Returns:
            CAInfo or None if not found
        """
        endpoint = f"{self.ENDPOINT_CA}/{ca_name}"

        try:
            response = self.session.get(
                self._url(endpoint),
                timeout=self.config.timeout
            )
            data = self._handle_response(response)

            # Get certificate chain
            chain = []
            for cert_b64 in data.get("certificate_chain", []):
                chain.append(base64.b64decode(cert_b64))

            return CAInfo(
                ca_id=data.get("id", 0),
                ca_name=data.get("name", ca_name),
                subject_dn=data.get("subject_dn", ""),
                certificate=base64.b64decode(data.get("certificate", "")),
                certificate_chain=chain,
                status=data.get("status", "active")
            )
        except EJBCANotFoundError:
            return None

    def get_ca_certificate(self, ca_name: str) -> Optional[bytes]:
        """
        Get CA certificate by name.

        Returns:
            DER encoded CA certificate
        """
        endpoint = f"{self.ENDPOINT_CA}/{ca_name}/certificate"

        try:
            response = self.session.get(
                self._url(endpoint),
                timeout=self.config.timeout
            )
            data = self._handle_response(response)
            cert_b64 = data.get("certificate", "")
            return base64.b64decode(cert_b64) if cert_b64 else None
        except EJBCANotFoundError:
            return None

    # End Entity Operations

    def add_end_entity(self, entity: EndEntity) -> bool:
        """
        Add a new end entity (enrollment user).

        Args:
            entity: End entity to create

        Returns:
            True if created successfully
        """
        payload = {
            "username": entity.username,
            "password": entity.password,
            "subject_dn": entity.subject_dn,
            "ca_name": entity.ca_name,
            "certificate_profile_name": entity.certificate_profile_name,
            "end_entity_profile_name": entity.end_entity_profile_name,
            "token": entity.token_type,
            "status": "NEW"
        }

        if entity.email:
            payload["email"] = entity.email
        if entity.san:
            payload["subject_alt_name"] = entity.san

        response = self.session.post(
            self._url(self.ENDPOINT_END_ENTITY),
            json=payload,
            timeout=self.config.timeout
        )
        self._handle_response(response)
        return True

    def get_end_entity(self, username: str) -> Optional[dict]:
        """
        Get end entity by username.

        Returns:
            End entity data or None if not found
        """
        endpoint = f"{self.ENDPOINT_END_ENTITY}/{username}"

        try:
            response = self.session.get(
                self._url(endpoint),
                timeout=self.config.timeout
            )
            return self._handle_response(response)
        except EJBCANotFoundError:
            return None

    def delete_end_entity(self, username: str) -> bool:
        """
        Delete an end entity.

        Args:
            username: Username of the end entity to delete

        Returns:
            True if deleted successfully
        """
        endpoint = f"{self.ENDPOINT_END_ENTITY}/{username}"

        response = self.session.delete(
            self._url(endpoint),
            timeout=self.config.timeout
        )
        self._handle_response(response)
        return True

    def reset_end_entity_password(self, username: str, password: str) -> bool:
        """
        Reset end entity password (for re-enrollment).

        Args:
            username: Username of the end entity
            password: New password

        Returns:
            True if password was reset
        """
        endpoint = f"{self.ENDPOINT_END_ENTITY}/{username}/setstatus"
        payload = {
            "status": "NEW",
            "password": password
        }

        response = self.session.post(
            self._url(endpoint),
            json=payload,
            timeout=self.config.timeout
        )
        self._handle_response(response)
        return True

    # Profile Operations

    def list_certificate_profiles(self) -> list:
        """
        List available certificate profiles.

        Returns:
            List of profile names
        """
        response = self.session.get(
            self._url(self.ENDPOINT_CERT_PROFILE),
            timeout=self.config.timeout
        )
        data = self._handle_response(response)
        return data.get("certificate_profiles", [])

    def list_end_entity_profiles(self) -> list:
        """
        List available end entity profiles.

        Returns:
            List of profile names
        """
        response = self.session.get(
            self._url(self.ENDPOINT_EE_PROFILE),
            timeout=self.config.timeout
        )
        data = self._handle_response(response)
        return data.get("end_entity_profiles", [])

    # Health Check

    def health_check(self) -> bool:
        """
        Check if EJBCA is reachable and healthy.

        Returns:
            True if healthy
        """
        try:
            # Try to list CAs as a health check
            self.list_cas()
            return True
        except Exception as e:
            logger.error(f"EJBCA health check failed: {e}")
            return False
