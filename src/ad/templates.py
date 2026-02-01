"""
Certificate Template Manager.

Handles mapping between AD certificate templates and EJBCA profiles,
and provides policy information to the XCEP service.
"""

import logging
from dataclasses import dataclass
from typing import Optional
import yaml

from ..soap.types import (
    CertificatePolicy, PolicyResponse, OID, CAInfo,
    CertificateValidity, PrivateKeyAttributes
)
from ..ejbca.models import TemplateMapping

logger = logging.getLogger(__name__)


@dataclass
class TemplateMappingConfig:
    """Configuration for template mappings."""

    mapping_file: str  # Path to YAML mapping file
    default_ca_name: str
    default_ca_uri: str
    default_ee_profile: str = "EMPTY"
    default_cert_profile: str = "ENDUSER"


class TemplateManager:
    """
    Manages certificate template mappings and provides policies.

    This is the bridge between AD templates (what Windows expects)
    and EJBCA profiles (what the CA understands).
    """

    # Well-known OIDs
    OID_SHA256 = "2.16.840.1.101.3.4.2.1"
    OID_RSA = "1.2.840.113549.1.1.1"
    OID_CLIENT_AUTH = "1.3.6.1.5.5.7.3.2"
    OID_SERVER_AUTH = "1.3.6.1.5.5.7.3.1"
    OID_SMART_CARD_LOGON = "1.3.6.1.4.1.311.20.2.2"
    OID_EMAIL_PROTECTION = "1.3.6.1.5.5.7.3.4"
    OID_CODE_SIGNING = "1.3.6.1.5.5.7.3.3"

    def __init__(self, config: TemplateMappingConfig, ca_certificate: bytes = None):
        """
        Initialize template manager.

        Args:
            config: Template mapping configuration
            ca_certificate: DER encoded CA certificate for policy responses
        """
        self.config = config
        self.ca_certificate = ca_certificate or b""
        self.mappings: dict[str, TemplateMapping] = {}
        self._load_mappings()

    def _load_mappings(self) -> None:
        """Load template mappings from YAML file."""
        try:
            with open(self.config.mapping_file, "r") as f:
                data = yaml.safe_load(f)

            for mapping_data in data.get("mappings", []):
                mapping = TemplateMapping(
                    ad_template_name=mapping_data["ad_template"],
                    ad_template_oid=mapping_data.get("ad_template_oid", ""),
                    ejbca_end_entity_profile=mapping_data.get(
                        "ejbca_ee_profile", self.config.default_ee_profile
                    ),
                    ejbca_cert_profile=mapping_data.get(
                        "ejbca_cert_profile", self.config.default_cert_profile
                    ),
                    ejbca_ca_name=mapping_data.get(
                        "ejbca_ca_name", self.config.default_ca_name
                    ),
                    allowed_groups=mapping_data.get("allowed_groups", []),
                    auto_enrollment=mapping_data.get("auto_enrollment", False),
                    validity_override=mapping_data.get("validity", None)
                )
                self.mappings[mapping.ad_template_name.lower()] = mapping

            logger.info(f"Loaded {len(self.mappings)} template mappings")

        except FileNotFoundError:
            logger.warning(f"Mapping file not found: {self.config.mapping_file}")
            self._create_default_mappings()
        except Exception as e:
            logger.error(f"Error loading mappings: {e}")
            self._create_default_mappings()

    def _create_default_mappings(self) -> None:
        """Create default template mappings if no file exists."""
        # Use Microsoft's Certificate Template OID arc: 1.3.6.1.4.1.311.21.8.x
        # These are example OIDs - in production, use actual template OIDs from AD
        default_templates = [
            ("User", "1.3.6.1.4.1.311.21.8.1"),
            ("Computer", "1.3.6.1.4.1.311.21.8.2"),
            ("WebServer", "1.3.6.1.4.1.311.21.8.3"),
            ("DomainController", "1.3.6.1.4.1.311.21.8.4"),
        ]

        for name, oid in default_templates:
            self.mappings[name.lower()] = TemplateMapping(
                ad_template_name=name,
                ad_template_oid=oid,
                ejbca_end_entity_profile=self.config.default_ee_profile,
                ejbca_cert_profile=self.config.default_cert_profile,
                ejbca_ca_name=self.config.default_ca_name,
                auto_enrollment=(name in ["User", "Computer"])
            )

        logger.info("Created default template mappings")

    def get_mapping(self, template_name: str) -> Optional[TemplateMapping]:
        """
        Get mapping for a template by name.

        Args:
            template_name: AD template name (case-insensitive)

        Returns:
            TemplateMapping or None if not found
        """
        return self.mappings.get(template_name.lower())

    def get_all_mappings(self) -> list:
        """Get all configured mappings."""
        return list(self.mappings.values())

    @staticmethod
    def _extract_cn(dn: str) -> str:
        """
        Extract CN from a Distinguished Name (case-insensitive).

        Args:
            dn: Distinguished Name (e.g., "CN=Domain Users,OU=Groups,DC=example,DC=com")

        Returns:
            The CN value, or empty string if not found
        """
        import re
        match = re.search(r"cn=([^,]+)", dn, flags=re.IGNORECASE)
        return match.group(1).strip() if match else ""

    def is_user_allowed(self, template_name: str, user_groups: list) -> bool:
        """
        Check if user is allowed to use a template based on group membership.

        Comparison is case-insensitive and handles both:
        - Full DN matching (e.g., "CN=Domain Users,OU=Groups,DC=...")
        - CN-only matching (e.g., "Domain Users")

        Args:
            template_name: Template name
            user_groups: List of group DNs the user belongs to

        Returns:
            True if user is allowed
        """
        mapping = self.get_mapping(template_name)
        if not mapping:
            return False

        # If no groups specified, allow everyone
        if not mapping.allowed_groups:
            return True

        # Build normalized sets for comparison (case-insensitive)
        # Full DNs (lowercased)
        user_dns = {g.casefold() for g in user_groups}
        # Just the CN part (lowercased)
        user_cns = {self._extract_cn(g).casefold() for g in user_groups}

        for allowed_group in mapping.allowed_groups:
            allowed = allowed_group.strip()

            if "=" in allowed:
                # Looks like a full DN - compare against full DNs
                if allowed.casefold() in user_dns:
                    return True
            else:
                # Treat as CN/group name - compare against extracted CNs
                if allowed.casefold() in user_cns:
                    return True

        return False

    def get_policies_for_client(self, client_identity: str,
                                user_groups: list = None) -> PolicyResponse:
        """
        Get certificate policies available to a client.

        This is called by the XCEP service to build GetPoliciesResponse.

        Args:
            client_identity: Client principal name
            user_groups: Optional list of group DNs the client belongs to

        Returns:
            PolicyResponse with available policies, CAs, and OIDs
        """
        policies = []
        oids = []
        oid_index = 0  # this will be used as oIDReferenceID

        # Add common OIDs (value, name, group)
        common_oids = [
            (self.OID_SHA256, "SHA256", 1),  # Hash algorithm
            (self.OID_RSA, "RSA", 2),  # Key algorithm
            (self.OID_CLIENT_AUTH, "Client Authentication", 3),
            (self.OID_SERVER_AUTH, "Server Authentication", 3),
            (self.OID_EMAIL_PROTECTION, "Email Protection", 3),
        ]

        for oid_value, oid_name, group in common_oids:
            oids.append(OID(
                oid=oid_value,
                name=oid_name,
                group=group,
                reference_id=oid_index,
                default_name=oid_name
            ))
            oid_index += 1

        # Build policies from mappings
        for mapping in self.mappings.values():
            # Security check: if template requires group membership
            if mapping.allowed_groups:
                if user_groups is None:
                    # LDAP unavailable - skip templates that require group verification
                    # This prevents unauthorized access when we can't verify groups
                    logger.debug(
                        f"Skipping template '{mapping.ad_template_name}': "
                        f"requires group membership but LDAP unavailable"
                    )
                    continue
                elif not self.is_user_allowed(mapping.ad_template_name, user_groups):
                    # User not in allowed groups
                    continue

            # Require a numeric OID in mapping; skip if missing to avoid
            # non-deterministic Python hash-derived OIDs.
            if not mapping.ad_template_oid:
                logger.warning(
                    f"Mapping for template '{mapping.ad_template_name}' has no ad_template_oid; skipping"
                )
                continue

            # Create policy OID entry. Use group=0 for template OIDs by default.
            policy_oid = OID(
                oid=str(mapping.ad_template_oid),
                name=mapping.ad_template_name,
                group=0,
                reference_id=oid_index,
                default_name=mapping.ad_template_name
            )
            oids.append(policy_oid)

            # Parse validity
            validity_seconds = 31536000  # Default 1 year
            renewal_seconds = 5184000    # Default 60 days
            if mapping.validity_override:
                validity_seconds = self._parse_validity(mapping.validity_override)
                renewal_seconds = validity_seconds // 6  # Renewal at 5/6 of validity

            policy = CertificatePolicy(
                policy_oid=str(oid_index),
                common_name=mapping.ad_template_name,
                certificate_validity=CertificateValidity(
                    validity_period_seconds=validity_seconds,
                    renewal_period_seconds=renewal_seconds
                ),
                permission_enroll=True,
                permission_auto_enroll=mapping.auto_enrollment,
                private_key_attributes=PrivateKeyAttributes(
                    min_key_length=2048,
                    key_spec=1,  # AT_KEYEXCHANGE
                    algorithm_oid=self.OID_RSA
                ),
                hash_algorithm_oid=self.OID_SHA256
            )
            policies.append(policy)
            oid_index += 1

        # CA info
        cas = [
            CAInfo(
                ca_reference=0,
                ca_uri=self.config.default_ca_uri,
                certificate=self.ca_certificate,
                renewal_only=False
            )
        ]

        return PolicyResponse(
            policy_id=f"{self.config.default_ca_name}-Policy",
            policy_friendly_name=f"{self.config.default_ca_name} Certificate Policy",
            policies=policies,
            cas=cas,
            oids=oids
        )

    def _parse_validity(self, validity_str: str) -> int:
        """
        Parse validity string to seconds.

        Args:
            validity_str: e.g., "1y", "6mo", "365d", "8760h"

        Returns:
            Validity in seconds
        """
        try:
            if validity_str.endswith("y"):
                return int(validity_str[:-1]) * 365 * 24 * 3600
            elif validity_str.endswith("mo"):
                return int(validity_str[:-2]) * 30 * 24 * 3600
            elif validity_str.endswith("d"):
                return int(validity_str[:-1]) * 24 * 3600
            elif validity_str.endswith("h"):
                return int(validity_str[:-1]) * 3600
            else:
                return int(validity_str)
        except ValueError:
            return 31536000  # Default 1 year


class PolicyProvider:
    """
    Provides certificate policies to the XCEP service.

    This is a simplified interface that the XCEP service uses.
    """

    def __init__(self, template_manager: TemplateManager, ldap_client=None):
        """
        Initialize policy provider.

        Args:
            template_manager: Template manager for mappings
            ldap_client: Optional LDAP client for user group lookups
        """
        self.template_manager = template_manager
        self.ldap_client = ldap_client

    def _compute_groups_hash(self, groups: list) -> str:
        """Compute a stable hash of user groups for cache key.
        
        Args:
            groups: List of group DNs
            
        Returns:
            SHA256 hash of sorted groups
        """
        import hashlib
        # Sort groups for consistent hashing
        sorted_groups = sorted(g.lower() for g in groups)
        groups_str = "|".join(sorted_groups)
        return hashlib.sha256(groups_str.encode("utf-8")).hexdigest()[:16]

    def _get_user_groups(self, client_identity: str) -> list:
        """Get user groups from AD.

        First checks if groups are already cached in Flask's request context (g.user_groups)
        to avoid duplicate LDAP queries within the same request.

        Args:
            client_identity: Kerberos principal or username

        Returns:
            List of group DNs
        """
        # Check if groups are already fetched in this request (from before_request)
        try:
            from flask import has_request_context, g
            if has_request_context() and hasattr(g, "user_groups") and g.user_groups is not None:
                return g.user_groups
        except ImportError:
            pass  # Flask not available (e.g., in tests)

        user_groups = []

        if self.ldap_client:
            try:
                user_info = self.ldap_client.get_user_by_principal(client_identity)
                if user_info:
                    user_groups = user_info.get("groups", [])
                else:
                    # Try as computer
                    computer_name = client_identity.split("@")[0] if "@" in client_identity else client_identity
                    computer_info = self.ldap_client.get_computer_by_name(computer_name)
                    if computer_info:
                        user_groups = computer_info.get("groups", [])
            except Exception as e:
                logger.warning(f"Could not get groups for {client_identity}: {e}")

        return user_groups

    def get_groups_hash(self, client_identity: str) -> str:
        """Get groups hash for cache key without full policy lookup.
        
        Args:
            client_identity: Kerberos principal or username
            
        Returns:
            Groups hash string
        """
        user_groups = self._get_user_groups(client_identity)
        return self._compute_groups_hash(user_groups) if user_groups else "no_groups"

    def get_policies_for_client(self, client_identity: str) -> tuple[PolicyResponse, str]:
        """
        Get policies available to a client.

        Args:
            client_identity: Kerberos principal or username

        Returns:
            Tuple of (PolicyResponse, groups_hash)
        """
        user_groups = self._get_user_groups(client_identity)
        groups_hash = self._compute_groups_hash(user_groups) if user_groups else "no_groups"

        return (
            self.template_manager.get_policies_for_client(
                client_identity,
                user_groups
            ),
            groups_hash
        )
