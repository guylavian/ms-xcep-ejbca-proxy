"""
Active Directory LDAP Client.

Handles connections to AD and queries for certificate templates.
Uses ldap3 library for LDAP operations.
"""

import logging
from dataclasses import dataclass
from typing import Optional

from ldap3 import (
    Server, Connection, ALL, NTLM, SASL, KERBEROS,
    SUBTREE, BASE
)
from ldap3.core.exceptions import LDAPException

logger = logging.getLogger(__name__)


class LDAPError(Exception):`ççç
    """Base exception for LDAP operations."""
    pass


class LDAPAuthError(LDAPError):
    """LDAP authentication error."""
    pass


class LDAPConnectionError(LDAPError):
    """LDAP connection error."""
    pass


@dataclass
class LDAPConfig:
    """LDAP connection configuration."""

    server_url: str  # e.g., "ldap://dc.example.com" or "ldaps://dc.example.com"
    base_dn: str  # e.g., "DC=example,DC=com"

    # Authentication options
    use_kerberos: bool = True
    username: Optional[str] = None  # For NTLM auth: "DOMAIN\\username"
    password: Optional[str] = None

    # SSL options
    use_ssl: bool = False
    ca_cert_file: Optional[str] = None

    # Connection options
    connect_timeout: int = 10
    receive_timeout: int = 30


class ADLDAPClient:
    """
    Active Directory LDAP client.

    Handles LDAP operations for reading certificate templates
    and user/group information.
    """

    # Well-known AD locations
    PKI_SERVICES_DN = "CN=Public Key Services,CN=Services,CN=Configuration"
    CERT_TEMPLATES_DN = "CN=Certificate Templates"
    ENROLLMENT_SERVICES_DN = "CN=Enrollment Services"
    OID_DN = "CN=OID"

    def __init__(self, config: LDAPConfig):
        """
        Initialize LDAP client.

        Args:
            config: LDAP connection configuration
        """
        self.config = config
        self._connection: Optional[Connection] = None

    def connect(self) -> None:
        """Establish LDAP connection."""
        try:
            # Create server
            server = Server(
                self.config.server_url,
                get_info=ALL,
                connect_timeout=self.config.connect_timeout
            )

            # Create connection based on auth method
            if self.config.use_kerberos:
                self._connection = Connection(
                    server,
                    authentication=SASL,
                    sasl_mechanism=KERBEROS,
                    auto_bind=True,
                    receive_timeout=self.config.receive_timeout
                )
            elif self.config.username and self.config.password:
                self._connection = Connection(
                    server,
                    user=self.config.username,
                    password=self.config.password,
                    authentication=NTLM,
                    auto_bind=True,
                    receive_timeout=self.config.receive_timeout
                )
            else:
                # Anonymous bind
                self._connection = Connection(
                    server,
                    auto_bind=True,
                    receive_timeout=self.config.receive_timeout
                )

            logger.info(f"Connected to LDAP server: {self.config.server_url}")

        except LDAPException as e:
            logger.error(f"LDAP connection failed: {e}")
            raise LDAPConnectionError(f"Failed to connect to LDAP: {e}")

    def disconnect(self) -> None:
        """Close LDAP connection."""
        if self._connection:
            self._connection.unbind()
            self._connection = None

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.disconnect()

    @property
    def connection(self) -> Connection:
        """Get active connection or raise error."""
        if not self._connection or not self._connection.bound:
            raise LDAPConnectionError("Not connected to LDAP server")
        return self._connection

    def is_connected(self) -> bool:
        """Check if LDAP connection is active and bound."""
        try:
            return self._connection is not None and self._connection.bound
        except Exception:
            return False

    def _get_configuration_dn(self) -> str:
        """Get the Configuration naming context DN."""
        # Configuration NC is typically CN=Configuration,DC=domain,DC=com
        return f"CN=Configuration,{self.config.base_dn}"

    def _get_pki_services_dn(self) -> str:
        """Get the PKI Services container DN."""
        return f"{self.PKI_SERVICES_DN},{self._get_configuration_dn()}"

    def _get_cert_templates_dn(self) -> str:
        """Get the Certificate Templates container DN."""
        return f"{self.CERT_TEMPLATES_DN},{self._get_pki_services_dn()}"

    def get_certificate_templates(self) -> list:
        """
        Get all certificate templates from AD.

        Returns:
            List of CertificateTemplate dictionaries
        """
        templates_dn = self._get_cert_templates_dn()

        # Certificate template attributes we need
        attributes = [
            "cn",  # Common Name
            "displayName",  # Display Name
            "msPKI-Cert-Template-OID",  # Template OID
            "msPKI-Template-Schema-Version",  # Schema version
            "msPKI-Private-Key-Flag",  # Private key flags
            "msPKI-Certificate-Name-Flag",  # Subject name flags
            "msPKI-Enrollment-Flag",  # Enrollment flags
            "msPKI-RA-Signature",  # RA signature required
            "msPKI-Minimal-Key-Size",  # Minimum key size
            "pKIExpirationPeriod",  # Validity period
            "pKIOverlapPeriod",  # Renewal overlap period
            "pKIExtendedKeyUsage",  # Extended Key Usage OIDs
            "pKIDefaultKeySpec",  # Key specification
            "pKICriticalExtensions",  # Critical extensions
            "revision",  # Template revision
            "flags",  # General flags
            "nTSecurityDescriptor",  # Security descriptor (ACL)
        ]

        try:
            self.connection.search(
                search_base=templates_dn,
                search_filter="(objectClass=pKICertificateTemplate)",
                search_scope=SUBTREE,
                attributes=attributes
            )

            templates = []
            for entry in self.connection.entries:
                template = self._parse_template_entry(entry)
                templates.append(template)

            logger.info(f"Found {len(templates)} certificate templates")
            return templates

        except LDAPException as e:
            logger.error(f"Failed to get certificate templates: {e}")
            raise LDAPError(f"Failed to get certificate templates: {e}")

    def _parse_template_entry(self, entry) -> dict:
        """Parse LDAP entry into template dictionary."""
        template = {
            "dn": str(entry.entry_dn),
            "cn": self._get_attr(entry, "cn"),
            "display_name": self._get_attr(entry, "displayName"),
            "oid": self._get_attr(entry, "msPKI-Cert-Template-OID"),
            "schema_version": self._get_attr_int(entry, "msPKI-Template-Schema-Version", 1),
            "private_key_flags": self._get_attr_int(entry, "msPKI-Private-Key-Flag", 0),
            "subject_name_flags": self._get_attr_int(entry, "msPKI-Certificate-Name-Flag", 0),
            "enrollment_flags": self._get_attr_int(entry, "msPKI-Enrollment-Flag", 0),
            "ra_signature": self._get_attr_int(entry, "msPKI-RA-Signature", 0),
            "min_key_size": self._get_attr_int(entry, "msPKI-Minimal-Key-Size", 2048),
            "validity_period": self._parse_validity_period(entry, "pKIExpirationPeriod"),
            "renewal_period": self._parse_validity_period(entry, "pKIOverlapPeriod"),
            "extended_key_usage": self._get_attr_list(entry, "pKIExtendedKeyUsage"),
            "key_spec": self._get_attr_int(entry, "pKIDefaultKeySpec", 1),
            "critical_extensions": self._get_attr_list(entry, "pKICriticalExtensions"),
            "revision": self._get_attr_int(entry, "revision", 1),
            "flags": self._get_attr_int(entry, "flags", 0),
        }

        return template

    def _get_attr(self, entry, attr_name: str, default: str = "") -> str:
        """Get string attribute from entry."""
        try:
            value = getattr(entry, attr_name, None)
            if value:
                return str(value.value) if hasattr(value, 'value') else str(value)
        except Exception:
            pass
        return default

    def _get_attr_int(self, entry, attr_name: str, default: int = 0) -> int:
        """Get integer attribute from entry."""
        try:
            value = getattr(entry, attr_name, None)
            if value:
                val = value.value if hasattr(value, 'value') else value
                return int(val)
        except Exception:
            pass
        return default

    def _get_attr_list(self, entry, attr_name: str) -> list:
        """Get list attribute from entry."""
        try:
            value = getattr(entry, attr_name, None)
            if value:
                val = value.values if hasattr(value, 'values') else value
                return list(val) if val else []
        except Exception:
            pass
        return []

    def _parse_validity_period(self, entry, attr_name: str) -> int:
        """
        Parse AD validity period (stored as negative 100-nanosecond intervals).

        Returns validity in seconds.
        """
        try:
            value = getattr(entry, attr_name, None)
            if value:
                raw_value = value.value if hasattr(value, 'value') else value
                if isinstance(raw_value, bytes):
                    # Convert from little-endian 8-byte signed integer
                    import struct
                    intervals = struct.unpack('<q', raw_value)[0]
                    # Convert from negative 100-nanosecond intervals to seconds
                    seconds = abs(intervals) // 10_000_000
                    return seconds
        except Exception as e:
            logger.debug(f"Failed to parse validity period: {e}")
        return 31536000  # Default: 1 year

    def get_template_by_name(self, template_name: str) -> Optional[dict]:
        """
        Get a specific certificate template by name.

        Args:
            template_name: Template CN or display name

        Returns:
            Template dictionary or None if not found
        """
        templates_dn = self._get_cert_templates_dn()

        try:
            self.connection.search(
                search_base=templates_dn,
                search_filter=f"(&(objectClass=pKICertificateTemplate)"
                              f"(|(cn={template_name})(displayName={template_name})))",
                search_scope=SUBTREE,
                attributes=["*"]
            )

            if self.connection.entries:
                return self._parse_template_entry(self.connection.entries[0])
            return None

        except LDAPException as e:
            logger.error(f"Failed to get template {template_name}: {e}")
            return None

    def get_user_groups(self, user_dn: str) -> list:
        """
        Get groups that a user belongs to (including nested groups).

        Args:
            user_dn: User's distinguished name

        Returns:
            List of group DNs
        """
        try:
            # Use memberOf attribute with LDAP_MATCHING_RULE_IN_CHAIN for nested groups
            self.connection.search(
                search_base=user_dn,
                search_filter="(objectClass=*)",
                search_scope=BASE,
                attributes=["memberOf"]
            )

            if self.connection.entries:
                return self._get_attr_list(self.connection.entries[0], "memberOf")
            return []

        except LDAPException as e:
            logger.error(f"Failed to get user groups: {e}")
            return []

    def get_user_by_principal(self, principal: str) -> Optional[dict]:
        """
        Get user by Kerberos principal name.

        Args:
            principal: Kerberos principal (e.g., "user@DOMAIN.COM")

        Returns:
            User dictionary with DN and attributes
        """
        # Parse principal - handle both user@domain and domain\\user
        if "@" in principal:
            username = principal.split("@")[0]
        elif "\\" in principal:
            username = principal.split("\\")[1]
        else:
            username = principal

        try:
            self.connection.search(
                search_base=self.config.base_dn,
                search_filter=f"(&(objectClass=user)(sAMAccountName={username}))",
                search_scope=SUBTREE,
                attributes=["distinguishedName", "sAMAccountName", "userPrincipalName",
                            "memberOf", "objectSid"]
            )

            if self.connection.entries:
                entry = self.connection.entries[0]
                return {
                    "dn": str(entry.entry_dn),
                    "sam_account_name": self._get_attr(entry, "sAMAccountName"),
                    "upn": self._get_attr(entry, "userPrincipalName"),
                    "groups": self._get_attr_list(entry, "memberOf"),
                }
            return None

        except LDAPException as e:
            logger.error(f"Failed to get user {principal}: {e}")
            return None

    def get_computer_by_name(self, computer_name: str) -> Optional[dict]:
        """
        Get computer account by name.

        Args:
            computer_name: Computer name (with or without trailing $)

        Returns:
            Computer dictionary with DN and attributes
        """
        # Ensure computer name ends with $
        if not computer_name.endswith("$"):
            computer_name = f"{computer_name}$"

        try:
            self.connection.search(
                search_base=self.config.base_dn,
                search_filter=f"(&(objectClass=computer)(sAMAccountName={computer_name}))",
                search_scope=SUBTREE,
                attributes=["distinguishedName", "sAMAccountName", "dNSHostName",
                            "memberOf", "objectSid", "operatingSystem"]
            )

            if self.connection.entries:
                entry = self.connection.entries[0]
                return {
                    "dn": str(entry.entry_dn),
                    "sam_account_name": self._get_attr(entry, "sAMAccountName"),
                    "dns_name": self._get_attr(entry, "dNSHostName"),
                    "groups": self._get_attr_list(entry, "memberOf"),
                    "os": self._get_attr(entry, "operatingSystem"),
                }
            return None

        except LDAPException as e:
            logger.error(f"Failed to get computer {computer_name}: {e}")
            return None

    def get_enrollment_services(self) -> list:
        """
        Get enrollment services (CAs) registered in AD.

        Returns:
            List of enrollment service dictionaries
        """
        services_dn = f"{self.ENROLLMENT_SERVICES_DN},{self._get_pki_services_dn()}"

        try:
            self.connection.search(
                search_base=services_dn,
                search_filter="(objectClass=pKIEnrollmentService)",
                search_scope=SUBTREE,
                attributes=["cn", "displayName", "dNSHostName",
                            "certificateTemplates", "cACertificate"]
            )

            services = []
            for entry in self.connection.entries:
                services.append({
                    "cn": self._get_attr(entry, "cn"),
                    "display_name": self._get_attr(entry, "displayName"),
                    "dns_name": self._get_attr(entry, "dNSHostName"),
                    "templates": self._get_attr_list(entry, "certificateTemplates"),
                    "ca_certificate": self._get_attr(entry, "cACertificate"),
                })

            return services

        except LDAPException as e:
            logger.error(f"Failed to get enrollment services: {e}")
            return []
