"""
LDAP client interface.

Defines the protocol for directory service backends (AD, OpenLDAP, etc.)
"""

from dataclasses import dataclass
from typing import Optional, List, Dict, Any, Protocol, runtime_checkable


class LDAPError(Exception):
    """Base exception for LDAP operations."""
    pass


class LDAPConnectionError(LDAPError):
    """LDAP connection or authentication failure."""
    pass


class LDAPSearchError(LDAPError):
    """LDAP search operation failure."""
    pass


@dataclass
class UserInfo:
    """User information from directory."""
    dn: str
    username: str
    principal: Optional[str]  # Kerberos principal
    email: Optional[str]
    groups: List[str]  # Group DNs
    attributes: Dict[str, Any]  # Raw LDAP attributes


@dataclass
class ComputerInfo:
    """Computer account information from directory."""
    dn: str
    name: str
    dns_name: Optional[str]
    groups: List[str]  # Group DNs
    attributes: Dict[str, Any]


@runtime_checkable
class LDAPClient(Protocol):
    """
    Protocol for LDAP/Directory clients.

    Implementations should provide methods for:
    - Connection management
    - User and computer lookups
    - Group membership queries
    """

    def is_connected(self) -> bool:
        """
        Check if connected to LDAP server.

        Returns:
            True if connected, False otherwise
        """
        ...

    def connect(self) -> None:
        """
        Establish connection to LDAP server.

        Raises:
            LDAPConnectionError: If connection fails
        """
        ...

    def disconnect(self) -> None:
        """
        Close LDAP connection.
        """
        ...

    def get_user_by_principal(self, principal: str) -> Optional[Dict[str, Any]]:
        """
        Look up user by Kerberos principal.

        Args:
            principal: Kerberos principal (e.g., "user@REALM")

        Returns:
            Dict with user info including 'groups' list, or None if not found

        Raises:
            LDAPSearchError: On search failure
        """
        ...

    def get_user_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        """
        Look up user by sAMAccountName.

        Args:
            username: Windows username (without domain)

        Returns:
            Dict with user info including 'groups' list, or None if not found

        Raises:
            LDAPSearchError: On search failure
        """
        ...

    def get_computer_by_name(self, computer_name: str) -> Optional[Dict[str, Any]]:
        """
        Look up computer account.

        Args:
            computer_name: Computer name (with or without trailing $)

        Returns:
            Dict with computer info including 'groups' list, or None if not found

        Raises:
            LDAPSearchError: On search failure
        """
        ...

    def get_group_members(self, group_dn: str) -> List[str]:
        """
        Get members of a group.

        Args:
            group_dn: Distinguished name of the group

        Returns:
            List of member DNs

        Raises:
            LDAPSearchError: On search failure
        """
        ...

    def is_member_of(self, user_dn: str, group_dn: str, recursive: bool = True) -> bool:
        """
        Check if user is member of group.

        Args:
            user_dn: User's distinguished name
            group_dn: Group's distinguished name
            recursive: Check nested groups

        Returns:
            True if user is member, False otherwise

        Raises:
            LDAPSearchError: On search failure
        """
        ...
