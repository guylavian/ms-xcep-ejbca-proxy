"""
Exception hierarchy for MS-XCEP/WSTEP proxy.

All domain exceptions inherit from ProxyError and include:
- error_code: Machine-readable code for logging/metrics
- http_status: Suggested HTTP status code
- soap_fault_code: SOAP fault code (Sender/Receiver)
"""

from dataclasses import dataclass
from typing import Optional


@dataclass
class ErrorContext:
    """Additional context for error reporting."""
    client_identity: Optional[str] = None
    template_name: Optional[str] = None
    request_id: Optional[str] = None
    details: Optional[str] = None


class ProxyError(Exception):
    """
    Base exception for all proxy errors.

    Attributes:
        error_code: Machine-readable error code
        http_status: HTTP status code
        soap_fault_code: SOAP fault code (Sender/Receiver)
        context: Additional error context
    """
    error_code: str = "PROXY_ERROR"
    http_status: int = 500
    soap_fault_code: str = "Receiver"  # Receiver = server error

    def __init__(self, message: str, context: Optional[ErrorContext] = None):
        super().__init__(message)
        self.message = message
        self.context = context or ErrorContext()


# =============================================================================
# Authentication / Authorization Errors
# =============================================================================

class AuthenticationError(ProxyError):
    """Client authentication failed."""
    error_code = "AUTH_FAILED"
    http_status = 401
    soap_fault_code = "Sender"


class KerberosError(AuthenticationError):
    """Kerberos-specific authentication error."""
    error_code = "KERBEROS_FAILED"


class AuthorizationError(ProxyError):
    """Client not authorized for requested operation."""
    error_code = "AUTHORIZATION_DENIED"
    http_status = 403
    soap_fault_code = "Sender"


# =============================================================================
# Enrollment Errors
# =============================================================================

class EnrollmentError(ProxyError):
    """Certificate enrollment failed."""
    error_code = "ENROLLMENT_FAILED"
    http_status = 500
    soap_fault_code = "Receiver"


class ValidationError(EnrollmentError):
    """Request validation failed (bad CSR, invalid parameters)."""
    error_code = "VALIDATION_FAILED"
    http_status = 400
    soap_fault_code = "Sender"


class CSRError(ValidationError):
    """CSR parsing or validation error."""
    error_code = "INVALID_CSR"


class SubjectMismatchError(ValidationError):
    """CSR subject doesn't match expected value."""
    error_code = "SUBJECT_MISMATCH"


# =============================================================================
# Configuration Errors
# =============================================================================

class ConfigurationError(ProxyError):
    """Configuration error preventing operation."""
    error_code = "CONFIG_ERROR"
    http_status = 500
    soap_fault_code = "Receiver"


# =============================================================================
# CA Backend Errors
# =============================================================================

class CAError(ProxyError):
    """Certificate Authority backend error."""
    error_code = "CA_ERROR"
    http_status = 502
    soap_fault_code = "Receiver"


class CAConnectionError(CAError):
    """Cannot connect to CA backend."""
    error_code = "CA_CONNECTION_ERROR"
    http_status = 503


class CAValidationError(CAError):
    """CA rejected the request (invalid profile, CSR, etc.)."""
    error_code = "CA_VALIDATION_ERROR"
    http_status = 400
    soap_fault_code = "Sender"


class CANotConfiguredError(CAError):
    """CA backend not configured."""
    error_code = "CA_NOT_CONFIGURED"
    http_status = 503


# =============================================================================
# LDAP Errors
# =============================================================================

class LDAPError(ProxyError):
    """LDAP/Directory service error."""
    error_code = "LDAP_ERROR"
    http_status = 502
    soap_fault_code = "Receiver"


class LDAPConnectionError(LDAPError):
    """Cannot connect to LDAP server."""
    error_code = "LDAP_CONNECTION_ERROR"
    http_status = 503


class LDAPSearchError(LDAPError):
    """LDAP search operation failed."""
    error_code = "LDAP_SEARCH_ERROR"


# =============================================================================
# Template Errors
# =============================================================================

class TemplateError(ProxyError):
    """Certificate template error."""
    error_code = "TEMPLATE_ERROR"
    http_status = 400
    soap_fault_code = "Sender"


class TemplateNotFoundError(TemplateError):
    """Requested template not configured."""
    error_code = "TEMPLATE_NOT_FOUND"
    http_status = 404


class TemplateAccessDeniedError(TemplateError):
    """User not authorized for this template."""
    error_code = "TEMPLATE_ACCESS_DENIED"
    http_status = 403


# =============================================================================
# Cache Errors
# =============================================================================

class CacheError(ProxyError):
    """Cache backend error (non-fatal, operations continue)."""
    error_code = "CACHE_ERROR"
    http_status = 500
    soap_fault_code = "Receiver"
