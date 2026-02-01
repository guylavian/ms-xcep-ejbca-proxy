"""
Certificate Enrollment Handler.

Bridges WSTEP requests to EJBCA enrollment operations.
"""

import logging
import secrets
import string
from typing import List
from typing import Optional

from .ad.ldap_client import ADLDAPClient
from .ad.templates import TemplateManager
from .ejbca.client import EJBCAClient, EJBCAError, EJBCAValidationError
from .ejbca.models import EndEntity, EnrollmentRequest
from .soap.wstep_service import EnrollmentResult, DispositionStatus, RequestType
from .utils.crypto import (
    parse_csr, get_csr_subject, get_csr_common_name, csr_to_base64,
    get_certificate_info, extract_principal_cn
)
from .utils.logging import AuditLogger

logger = logging.getLogger(__name__)


class EnrollmentHandler:
    """
    Handles certificate enrollment requests.

    Takes CSR and client identity from WSTEP service,
    maps to EJBCA profiles, and returns enrolled certificate.
    """

    def __init__(self, ejbca_client: EJBCAClient, template_manager: TemplateManager,
                 audit_logger: AuditLogger = None, ldap_client: ADLDAPClient = None):
        """
        Initialize enrollment handler.

        Args:
            ejbca_client: EJBCA REST API client
            template_manager: Certificate template manager
            audit_logger: Optional audit logger
            ldap_client: Optional LDAP client for authorization checks
        """
        self.ejbca = ejbca_client
        self.templates = template_manager
        self.audit = audit_logger or AuditLogger()
        self.ldap_client = ldap_client

    def enroll(self, csr_data: bytes, client_identity: str,
               template_name: str, request_type: RequestType,
               client_ip: str = "") -> EnrollmentResult:
        """
        Process certificate enrollment request.

        Args:
            csr_data: PKCS#10 CSR data
            client_identity: Authenticated client principal
            template_name: Certificate template name
            request_type: Request type (Issue, Renew)
            client_ip: Client IP address (for audit logging)

        Returns:
            EnrollmentResult with certificate or error
        """
        request_id = self._generate_request_id()

        try:
            # Parse and validate CSR
            csr = parse_csr(csr_data)
            csr_subject = get_csr_subject(csr)
            csr_cn = get_csr_common_name(csr)

            logger.info(f"Processing enrollment request {request_id} for "
                        f"{client_identity}, template={template_name}, subject={csr_subject}")

            # Log enrollment request
            self.audit.log_enrollment_request(
                client_identity=client_identity,
                client_ip=client_ip,
                template_name=template_name,
                csr_subject=csr_subject,
                request_id=request_id
            )

            # Get template mapping
            mapping = self.templates.get_mapping(template_name)
            if not mapping:
                logger.warning(f"No mapping found for template: {template_name}")
                return self._create_error_result(
                    f"Template '{template_name}' not configured",
                    request_id
                )

            # Authorization check - verify user is allowed to use this template
            auth_result = self._check_template_authorization(
                client_identity, template_name, mapping, request_id
            )
            if auth_result is not None:
                # Authorization failed - return error result
                return auth_result

            # Generate username for EJBCA (includes template for uniqueness)
            username = self._generate_username(client_identity, csr_cn, template_name)

            # Generate password for enrollment
            password = self._generate_password()

            # Prepare CSR for EJBCA (base64 encoded)
            csr_b64 = csr_to_base64(csr_data)

            # Check if end entity already exists
            existing_ee = self.ejbca.get_end_entity(username)
            if existing_ee:
                if request_type == RequestType.RENEW:
                    # Reset password for re-enrollment
                    self.ejbca.reset_end_entity_password(username, password)
                    logger.info(f"Reset password for existing end entity: {username}")
                else:
                    # Delete and recreate for new enrollment
                    self.ejbca.delete_end_entity(username)
                    logger.info(f"Deleted existing end entity: {username}")
                    # Create new end entity after deletion
                    ee = EndEntity(
                        username=username,
                        password=password,
                        subject_dn=csr_subject,
                        ca_name=mapping.ejbca_ca_name,
                        end_entity_profile_name=mapping.ejbca_end_entity_profile,
                        certificate_profile_name=mapping.ejbca_cert_profile,
                    )
                    self.ejbca.add_end_entity(ee)
                    logger.info(f"Created new end entity: {username}")
            else:
                # Create new end entity
                ee = EndEntity(
                    username=username,
                    password=password,
                    subject_dn=csr_subject,
                    ca_name=mapping.ejbca_ca_name,
                    end_entity_profile_name=mapping.ejbca_end_entity_profile,
                    certificate_profile_name=mapping.ejbca_cert_profile,
                )
                self.ejbca.add_end_entity(ee)
                logger.info(f"Created end entity: {username}")

            # Create enrollment request
            enroll_request = EnrollmentRequest(
                csr=csr_b64,
                username=username,
                password=password,
                certificate_profile_name=mapping.ejbca_cert_profile,
                end_entity_profile_name=mapping.ejbca_end_entity_profile,
                ca_name=mapping.ejbca_ca_name,
                include_chain=True
            )

            # Enroll certificate
            response = self.ejbca.enroll_pkcs10(enroll_request)

            # Get certificate info for logging
            from .utils.crypto import parse_certificate
            cert = parse_certificate(response.certificate)
            cert_info = get_certificate_info(cert)

            # Log success
            self.audit.log_enrollment_success(
                client_identity=client_identity,
                template_name=template_name,
                serial_number=cert_info["serial_number"],
                subject_dn=cert_info["subject"],
                issuer_dn=cert_info["issuer"],
                not_after=cert_info["not_after"],
                request_id=request_id
            )

            logger.info(f"Certificate issued for {username}, "
                        f"serial={cert_info['serial_number']}")

            return EnrollmentResult(
                status=DispositionStatus.ISSUED,
                certificate=response.certificate,
                certificate_chain=response.certificate_chain,
                request_id=request_id,
                disposition_message="Certificate issued successfully"
            )

        except EJBCAValidationError as e:
            logger.warning(f"EJBCA validation error: {e}")
            self.audit.log_enrollment_failure(
                client_identity=client_identity,
                template_name=template_name,
                error_code="VALIDATION_ERROR",
                error_message=str(e),
                request_id=request_id
            )
            return self._create_error_result(str(e), request_id)

        except EJBCAError as e:
            logger.error(f"EJBCA error: {e}")
            self.audit.log_enrollment_failure(
                client_identity=client_identity,
                template_name=template_name,
                error_code="EJBCA_ERROR",
                error_message=str(e),
                request_id=request_id
            )
            return self._create_error_result("Certificate authority error", request_id)

        except Exception as e:
            logger.exception(f"Enrollment error: {e}")
            self.audit.log_enrollment_failure(
                client_identity=client_identity,
                template_name=template_name,
                error_code="INTERNAL_ERROR",
                error_message=str(e),
                request_id=request_id
            )
            return self._create_error_result("Internal enrollment error", request_id)

    def _check_template_authorization(self, client_identity: str, template_name: str,
                                      mapping, request_id: str) -> Optional[EnrollmentResult]:
        """
        Check if client is authorized to use the requested template.

        Args:
            client_identity: Authenticated client principal
            template_name: Requested template name
            mapping: Template mapping object
            request_id: Request ID for logging

        Returns:
            EnrollmentResult if authorization fails, None if authorized
        """
        # If template has no allowed_groups restriction, allow everyone
        if not mapping.allowed_groups:
            return None

        # Template has group restrictions - we MUST verify groups
        user_groups = self._get_user_groups(client_identity)

        if user_groups is None:
            # LDAP not available and template requires group check
            # Deny by default for security
            logger.warning(
                f"Authorization denied for {client_identity} on template {template_name}: "
                f"LDAP unavailable and template requires group membership"
            )
            self.audit.log_enrollment_failure(
                client_identity=client_identity,
                template_name=template_name,
                error_code="AUTHORIZATION_DENIED",
                error_message="Cannot verify group membership (LDAP unavailable)",
                request_id=request_id
            )
            return self._create_error_result(
                f"Cannot verify authorization for template '{template_name}'",
                request_id
            )

        # Check if user is in any allowed group
        if not self.templates.is_user_allowed(template_name, user_groups):
            logger.warning(
                f"Authorization denied for {client_identity} on template {template_name}: "
                f"user not in allowed groups"
            )
            self.audit.log_enrollment_failure(
                client_identity=client_identity,
                template_name=template_name,
                error_code="AUTHORIZATION_DENIED",
                error_message="User not authorized for this template",
                request_id=request_id
            )
            return self._create_error_result(
                f"Not authorized to enroll for template '{template_name}'",
                request_id
            )

        logger.debug(f"Authorization granted for {client_identity} on template {template_name}")
        return None

    def _get_user_groups(self, client_identity: str) -> Optional[List[str]]:
        """
        Get user's group memberships from LDAP.

        First checks if groups are already cached in Flask's request context (g.user_groups)
        to avoid duplicate LDAP queries within the same request.

        Args:
            client_identity: Kerberos principal or username

        Returns:
            List of group DNs, or None if LDAP unavailable
        """
        # Check if groups are already fetched in this request (from before_request)
        try:
            from flask import has_request_context, g
            if has_request_context() and hasattr(g, "user_groups"):
                # Return whatever was cached (could be None, [], or list of groups)
                return g.user_groups
        except ImportError:
            pass  # Flask not available (e.g., in tests)

        if not self.ldap_client:
            return None

        try:
            user_info = self.ldap_client.get_user_by_principal(client_identity)
            if user_info:
                return user_info.get("groups", [])

            # Try as computer account
            computer_name = client_identity.split("@")[0] if "@" in client_identity else client_identity
            computer_info = self.ldap_client.get_computer_by_name(computer_name)
            if computer_info:
                return computer_info.get("groups", [])

            # User/computer not found in LDAP - return empty list (not None)
            # This allows templates without group restrictions to work
            return []

        except Exception as e:
            logger.warning(f"LDAP lookup failed for {client_identity}: {e}")
            return None

    def _generate_username(self, principal: str, csr_cn: str = None,
                           template_name: str = None) -> str:
        """
        Generate EJBCA username from client identity.

        Creates a unique username by combining principal name, realm, and
        optionally the template to avoid collisions between users/computers
        with similar names.

        Args:
            principal: Kerberos principal (e.g., "user@REALM" or "HOST$@REALM")
            csr_cn: Common Name from CSR (optional)
            template_name: Certificate template name (optional)

        Returns:
            Username suitable for EJBCA
        """
        import hashlib

        # Extract name and realm from principal
        name = extract_principal_cn(principal)
        realm = ""
        if "@" in principal:
            realm = principal.split("@")[-1]

        # Determine entity type (computer accounts end with $)
        entity_type = "computer" if name.endswith("$") else "user"

        # Build base username
        base_name = name.rstrip("$")  # Remove trailing $ for computers

        # Add short hash for uniqueness (based on full principal + template)
        unique_input = f"{principal}:{template_name or ''}"
        short_hash = hashlib.sha256(unique_input.encode()).hexdigest()[:8]

        # Combine: name_type_hash (e.g., "jdoe_user_a1b2c3d4")
        username = f"{base_name}_{entity_type}_{short_hash}"

        # Sanitize for EJBCA (alphanumeric, underscores, hyphens)
        safe_name = "".join(c if c.isalnum() or c in "_-." else "_" for c in username)

        # Limit length
        if len(safe_name) > 64:
            safe_name = safe_name[:64]

        return safe_name

    def _generate_password(self, length: int = 32) -> str:
        """
        Generate a secure random password for enrollment.

        Args:
            length: Password length

        Returns:
            Random password string
        """
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
        return "".join(secrets.choice(alphabet) for _ in range(length))

    def _generate_request_id(self) -> str:
        """Generate a unique request tracking ID."""
        return secrets.token_hex(8)

    def _create_error_result(self, message: str, request_id: str) -> EnrollmentResult:
        """Create an error enrollment result."""
        return EnrollmentResult(
            status=DispositionStatus.ERROR,
            error_message=message,
            request_id=request_id,
            disposition_message=message
        )
