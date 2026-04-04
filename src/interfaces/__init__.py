"""
Interface definitions (Protocols/ABCs) for dependency injection.

This module defines abstract interfaces that allow for:
- Clean dependency injection
- Easy mocking in tests
- Swappable implementations (e.g., different CA backends)
"""

from .ca import CAClient, CAError, CAValidationError
from .cache import CacheBackend
from .ldap import LDAPClient, LDAPError

__all__ = [
    "CAClient",
    "CAError",
    "CAValidationError",
    "LDAPClient",
    "LDAPError",
    "CacheBackend",
]
