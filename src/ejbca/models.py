"""
EJBCA data models.

Represents EJBCA entities like Certificate Profiles, End Entity Profiles,
and Certificate Authorities.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional


class EndEntityStatus(Enum):
    """EJBCA end entity status codes."""

    NEW = 10
    FAILED = 11
    INITIALIZED = 20
    INPROCESS = 30
    GENERATED = 40
    REVOKED = 50
    HISTORICAL = 60
    KEYRECOVERY = 70
    WAITINGFORREVOCATION = 80


class RevocationReason(Enum):
    """Certificate revocation reasons (RFC 5280)."""

    UNSPECIFIED = 0
    KEY_COMPROMISE = 1
    CA_COMPROMISE = 2
    AFFILIATION_CHANGED = 3
    SUPERSEDED = 4
    CESSATION_OF_OPERATION = 5
    CERTIFICATE_HOLD = 6
    REMOVE_FROM_CRL = 8
    PRIVILEGE_WITHDRAWN = 9
    AA_COMPROMISE = 10


@dataclass
class CertificateProfile:
    """EJBCA Certificate Profile."""

    profile_id: int
    profile_name: str
    description: str = ""
    validity: str = "1y"  # e.g., "1y", "6mo", "365d"
    key_usages: list = field(default_factory=list)
    extended_key_usages: list = field(default_factory=list)
    allow_key_usage_override: bool = False


@dataclass
class EndEntityProfile:
    """EJBCA End Entity Profile."""

    profile_id: int
    profile_name: str
    description: str = ""
    subject_dn_attributes: list = field(default_factory=list)
    san_attributes: list = field(default_factory=list)
    available_cas: list = field(default_factory=list)
    available_cert_profiles: list = field(default_factory=list)


@dataclass
class CAInfo:
    """EJBCA Certificate Authority information."""

    ca_id: int
    ca_name: str
    subject_dn: str
    certificate: bytes  # DER encoded
    certificate_chain: list = field(default_factory=list)  # List of DER encoded
    status: str = "active"
    validity_end: Optional[datetime] = None


@dataclass
class EndEntity:
    """EJBCA End Entity (user/device that requests certificates)."""

    username: str
    password: str
    subject_dn: str
    ca_name: str
    certificate_profile_name: str
    end_entity_profile_name: str
    token_type: str = "USERGENERATED"  # User generates keys
    status: EndEntityStatus = EndEntityStatus.NEW
    email: Optional[str] = None
    san: Optional[str] = None  # Subject Alternative Names


@dataclass
class EnrollmentRequest:
    """Certificate enrollment request to EJBCA."""

    csr: str  # Base64 encoded PKCS#10
    username: str
    password: str
    certificate_profile_name: str = "ENDUSER"
    end_entity_profile_name: str = "EMPTY"
    ca_name: str = ""
    include_chain: bool = True


@dataclass
class EnrollmentResponse:
    """Certificate enrollment response from EJBCA."""

    certificate: bytes  # DER encoded certificate
    certificate_chain: list = field(default_factory=list)  # List of DER encoded
    serial_number: str = ""
    subject_dn: str = ""
    issuer_dn: str = ""
    not_before: Optional[datetime] = None
    not_after: Optional[datetime] = None


@dataclass
class TemplateMapping:
    """Mapping between AD certificate template and EJBCA profiles."""

    ad_template_name: str
    ad_template_oid: str
    ejbca_end_entity_profile: str
    ejbca_cert_profile: str
    ejbca_ca_name: str
    allowed_groups: list = field(default_factory=list)  # AD groups that can use this
    auto_enrollment: bool = False
    validity_override: Optional[str] = None
