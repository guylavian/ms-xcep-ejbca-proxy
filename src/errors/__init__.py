"""
Centralized error handling for MS-XCEP/WSTEP proxy.

This module provides:
- Domain-specific exceptions hierarchy
- Error codes for audit logging
- SOAP fault mapping utilities
"""

from .exceptions import (
    ProxyError,
    AuthenticationError,
    AuthorizationError,
    EnrollmentError,
    ValidationError,
    ConfigurationError,
    CAError,
    CAConnectionError,
    CAValidationError,
    LDAPError,
    LDAPConnectionError,
    TemplateError,
    TemplateNotFoundError,
    CacheError,
)

from .fault_mapper import FaultMapper, SoapFault

__all__ = [
    # Base errors
    "ProxyError",
    # Authentication/Authorization
    "AuthenticationError",
    "AuthorizationError",
    # Enrollment
    "EnrollmentError",
    "ValidationError",
    # Configuration
    "ConfigurationError",
    # CA backend
    "CAError",
    "CAConnectionError",
    "CAValidationError",
    # LDAP
    "LDAPError",
    "LDAPConnectionError",
    # Templates
    "TemplateError",
    "TemplateNotFoundError",
    # Cache
    "CacheError",
    # Fault mapping
    "FaultMapper",
    "SoapFault",
]
