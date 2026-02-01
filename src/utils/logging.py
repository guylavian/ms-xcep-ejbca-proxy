"""
Structured logging configuration.

Uses structlog for structured logging suitable for SIEM integration.
"""

import logging
import sys
from datetime import datetime
from typing import Optional

import structlog


def configure_logging(
    level: str = "INFO",
    json_format: bool = False,
    log_file: Optional[str] = None
) -> None:
    """
    Configure structured logging for the application.

    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        json_format: If True, output logs as JSON (for SIEM)
        log_file: Optional file path for log output
    """
    # Convert level string to logging constant
    log_level = getattr(logging, level.upper(), logging.INFO)

    # Configure standard logging
    handlers = []

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)
    handlers.append(console_handler)

    # File handler if specified
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(log_level)
        handlers.append(file_handler)

    # Configure root logger
    logging.basicConfig(
        level=log_level,
        handlers=handlers,
        format="%(message)s"
    )

    # Configure structlog
    processors = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
    ]

    if json_format:
        # JSON output for SIEM
        processors.extend([
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer()
        ])
    else:
        # Human-readable output for development
        processors.extend([
            structlog.dev.ConsoleRenderer(colors=True)
        ])

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(log_level),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str) -> structlog.BoundLogger:
    """
    Get a structured logger for a module.

    Args:
        name: Logger name (usually __name__)

    Returns:
        Structlog BoundLogger
    """
    return structlog.get_logger(name)


class AuditLogger:
    """
    Specialized logger for security audit events.

    Logs certificate enrollment events with all relevant details
    for compliance and security monitoring.
    """

    def __init__(self, name: str = "audit"):
        """Initialize audit logger."""
        self.logger = structlog.get_logger(name)

    def log_enrollment_request(
        self,
        client_identity: str,
        client_ip: str,
        template_name: str,
        csr_subject: str,
        request_id: str = None
    ) -> None:
        """
        Log a certificate enrollment request.

        Args:
            client_identity: Authenticated client principal
            client_ip: Client IP address
            template_name: Requested certificate template
            csr_subject: Subject DN from CSR
            request_id: Optional request tracking ID
        """
        self.logger.info(
            "certificate_enrollment_request",
            event_type="enrollment_request",
            client_identity=client_identity,
            client_ip=client_ip,
            template_name=template_name,
            csr_subject=csr_subject,
            request_id=request_id,
            timestamp=datetime.utcnow().isoformat()
        )

    def log_enrollment_success(
        self,
        client_identity: str,
        template_name: str,
        serial_number: str,
        subject_dn: str,
        issuer_dn: str,
        not_after: str,
        request_id: str = None
    ) -> None:
        """
        Log successful certificate enrollment.

        Args:
            client_identity: Authenticated client principal
            template_name: Certificate template used
            serial_number: Issued certificate serial number
            subject_dn: Certificate subject DN
            issuer_dn: Certificate issuer DN
            not_after: Certificate expiration date
            request_id: Optional request tracking ID
        """
        self.logger.info(
            "certificate_enrollment_success",
            event_type="enrollment_success",
            client_identity=client_identity,
            template_name=template_name,
            serial_number=serial_number,
            subject_dn=subject_dn,
            issuer_dn=issuer_dn,
            not_after=not_after,
            request_id=request_id,
            timestamp=datetime.utcnow().isoformat()
        )

    def log_enrollment_failure(
        self,
        client_identity: str,
        template_name: str,
        error_code: str,
        error_message: str,
        request_id: str = None
    ) -> None:
        """
        Log failed certificate enrollment.

        Args:
            client_identity: Authenticated client principal
            template_name: Requested certificate template
            error_code: Error code
            error_message: Error description
            request_id: Optional request tracking ID
        """
        self.logger.warning(
            "certificate_enrollment_failure",
            event_type="enrollment_failure",
            client_identity=client_identity,
            template_name=template_name,
            error_code=error_code,
            error_message=error_message,
            request_id=request_id,
            timestamp=datetime.utcnow().isoformat()
        )

    def log_policy_request(
        self,
        client_identity: str,
        client_ip: str,
        policies_returned: int
    ) -> None:
        """
        Log a GetPolicies request.

        Args:
            client_identity: Authenticated client principal
            client_ip: Client IP address
            policies_returned: Number of policies returned
        """
        self.logger.info(
            "policy_request",
            event_type="policy_request",
            client_identity=client_identity,
            client_ip=client_ip,
            policies_returned=policies_returned,
            timestamp=datetime.utcnow().isoformat()
        )

    def log_authentication_failure(
        self,
        client_ip: str,
        auth_method: str,
        error: str
    ) -> None:
        """
        Log authentication failure.

        Args:
            client_ip: Client IP address
            auth_method: Authentication method attempted
            error: Error description
        """
        self.logger.warning(
            "authentication_failure",
            event_type="auth_failure",
            client_ip=client_ip,
            auth_method=auth_method,
            error=error,
            timestamp=datetime.utcnow().isoformat()
        )

    def log_authorization_denied(
        self,
        client_identity: str,
        resource: str,
        reason: str
    ) -> None:
        """
        Log authorization denial.

        Args:
            client_identity: Authenticated client principal
            resource: Resource access was denied to
            reason: Reason for denial
        """
        self.logger.warning(
            "authorization_denied",
            event_type="authz_denied",
            client_identity=client_identity,
            resource=resource,
            reason=reason,
            timestamp=datetime.utcnow().isoformat()
        )
