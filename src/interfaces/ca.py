"""
Certificate Authority client interface.

Defines the protocol for CA backends (EJBCA, Dogtag, etc.)
"""

from dataclasses import dataclass
from typing import Optional, List, Protocol, runtime_checkable


class CAError(Exception):
    """Base exception for CA operations."""
    pass


class CAValidationError(CAError):
    """Validation error from CA (e.g., invalid CSR, profile mismatch)."""
    pass


@dataclass
class EndEntityInfo:
    """Information about an end entity in the CA."""
    username: str
    subject_dn: str
    ca_name: str
    end_entity_profile: str
    certificate_profile: str
    status: Optional[str] = None


@dataclass
class EnrollmentRequest:
    """Certificate enrollment request."""
    csr: str  # Base64-encoded PKCS#10 CSR
    username: str
    password: str
    certificate_profile_name: str
    end_entity_profile_name: str
    ca_name: str
    include_chain: bool = True


@dataclass
class EnrollmentResponse:
    """Certificate enrollment response."""
    certificate: bytes  # DER-encoded certificate
    certificate_chain: List[bytes]  # Chain certificates (DER)
    serial_number: Optional[str] = None


@runtime_checkable
class CAClient(Protocol):
    """
    Protocol for Certificate Authority clients.

    Implementations should provide methods for:
    - End entity management (add, get, delete, reset password)
    - Certificate enrollment (PKCS#10)
    - CA information retrieval
    """

    def health_check(self) -> bool:
        """
        Check if CA is reachable and operational.

        Returns:
            True if healthy, False otherwise
        """
        ...

    def get_ca_certificate(self, ca_name: str) -> bytes:
        """
        Get CA certificate in DER format.

        Args:
            ca_name: Name of the CA

        Returns:
            DER-encoded CA certificate

        Raises:
            CAError: If CA not found or communication error
        """
        ...

    def get_end_entity(self, username: str) -> Optional[EndEntityInfo]:
        """
        Get end entity information.

        Args:
            username: End entity username

        Returns:
            EndEntityInfo if found, None otherwise

        Raises:
            CAError: On communication error
        """
        ...

    def add_end_entity(self, entity: "EndEntity") -> None:
        """
        Add a new end entity.

        Args:
            entity: End entity to create

        Raises:
            CAError: If entity already exists or validation fails
        """
        ...

    def delete_end_entity(self, username: str) -> None:
        """
        Delete an end entity.

        Args:
            username: End entity username

        Raises:
            CAError: If entity not found or cannot be deleted
        """
        ...

    def reset_end_entity_password(self, username: str, password: str) -> None:
        """
        Reset end entity password for re-enrollment.

        Args:
            username: End entity username
            password: New password

        Raises:
            CAError: If entity not found
        """
        ...

    def enroll_pkcs10(self, request: EnrollmentRequest) -> EnrollmentResponse:
        """
        Enroll certificate using PKCS#10 CSR.

        Args:
            request: Enrollment request with CSR

        Returns:
            EnrollmentResponse with certificate and chain

        Raises:
            CAValidationError: If CSR validation fails
            CAError: On enrollment failure
        """
        ...


# For type hints in add_end_entity
@dataclass
class EndEntity:
    """End entity for certificate enrollment."""
    username: str
    password: str
    subject_dn: str
    ca_name: str
    end_entity_profile_name: str
    certificate_profile_name: str
    email: Optional[str] = None
    token_type: str = "USERGENERATED"  # CSR provided by user
