"""
Services layer - dependency injection and service creation.

This module provides a clean way to create all application services
with proper dependency injection.
"""

from dataclasses import dataclass
from typing import Any

from ..config import AppConfig
from ..utils.logging import get_logger, AuditLogger

logger = get_logger(__name__)


@dataclass
class Services:
    """Container for all application services."""
    cache: Any
    ca_client: Any
    ldap_client: Any
    template_manager: Any
    policy_provider: Any
    xcep_service: Any
    enrollment_handler: Any
    wstep_service: Any
    kerberos_auth: Any


def create_services(config: AppConfig) -> Services:
    """
    Create all application services with proper dependency injection.

    Args:
        config: Application configuration

    Returns:
        Services container with all initialized services
    """
    # Import here to avoid circular imports
    from ..ejbca.client import EJBCAClient, EJBCAConfig
    from ..ad.ldap_client import ADLDAPClient, LDAPConfig
    from ..ad.templates import TemplateManager, TemplateMappingConfig, PolicyProvider
    from ..cache.redis_cache import CacheConfig, create_cache
    from ..enrollment_handler import EnrollmentHandler
    from ..soap.xcep_service import XCEPService
    from ..soap.wstep_service import WSTEPService

    # Create cache
    cache_config = CacheConfig(
        enabled=config.cache_enabled,
        host=config.cache_host,
        port=config.cache_port
    )
    cache = create_cache(cache_config)

    # Create EJBCA client
    ca_client = None
    ca_cert = b""
    if config.ejbca_url:
        ejbca_config = EJBCAConfig(
            base_url=config.ejbca_url,
            client_cert_path=config.ejbca_client_cert,
            client_key_path=config.ejbca_client_key,
            ca_cert_path=config.ejbca_ca_cert,
            verify_ssl=config.ejbca_verify_ssl
        )
        ca_client = EJBCAClient(ejbca_config)

        # Get CA certificate for policy responses
        try:
            ca_cert = ca_client.get_ca_certificate(config.ejbca_default_ca)
        except Exception as e:
            logger.warning(f"Could not get CA certificate: {e}")
    else:
        logger.warning("EJBCA not configured - enrollment will fail")

    # Create LDAP client
    ldap_client = None
    if config.ldap_url:
        ldap_config = LDAPConfig(
            server_url=config.ldap_url,
            base_dn=config.ldap_base_dn,
            use_kerberos=config.ldap_use_kerberos,
            username=config.ldap_username,
            password=config.ldap_password
        )
        ldap_client = ADLDAPClient(ldap_config)
    else:
        logger.warning("LDAP not configured - group-based filtering disabled")

    # Create template manager
    ca_uri_host = config.public_fqdn if config.public_fqdn and config.public_fqdn != "0.0.0.0" else "localhost"
    template_config = TemplateMappingConfig(
        mapping_file=config.template_mapping_file or "config/template_mapping.yaml",
        default_ca_name=config.ejbca_default_ca,
        default_ca_uri=f"https://{ca_uri_host}:{config.port}/ADPolicyProvider_CES_Kerberos/service.svc/CES",
        default_ee_profile=config.ejbca_default_ee_profile,
        default_cert_profile=config.ejbca_default_cert_profile
    )
    template_manager = TemplateManager(template_config, ca_cert)

    # Create policy provider
    policy_provider = PolicyProvider(template_manager, ldap_client)

    # Create XCEP service
    xcep_service = XCEPService(policy_provider)

    # Create enrollment handler
    audit_logger = AuditLogger()
    enrollment_handler = None
    if ca_client:
        enrollment_handler = EnrollmentHandler(
            ca_client, template_manager, audit_logger, ldap_client
        )

    # Create WSTEP service
    wstep_service = WSTEPService(enrollment_handler)

    # Create Kerberos auth
    kerberos_auth = _create_kerberos_auth(config)

    return Services(
        cache=cache,
        ca_client=ca_client,
        ldap_client=ldap_client,
        template_manager=template_manager,
        policy_provider=policy_provider,
        xcep_service=xcep_service,
        enrollment_handler=enrollment_handler,
        wstep_service=wstep_service,
        kerberos_auth=kerberos_auth
    )


def _create_kerberos_auth(config: AppConfig):
    """Create Kerberos authentication handler."""
    from ..auth.kerberos import KerberosAuth, KerberosConfig, MockKerberosAuth

    if config.mock_kerberos:
        logger.warning("Using mock Kerberos authentication - FOR DEVELOPMENT ONLY")
        return MockKerberosAuth(config.mock_principal)

    if config.kerberos_principal:
        kerberos_config = KerberosConfig(
            service_principal=config.kerberos_principal,
            keytab_path=config.kerberos_keytab,
            allow_fallback=config.kerberos_allow_fallback
        )
        try:
            return KerberosAuth(kerberos_config)
        except Exception as e:
            logger.error(f"Failed to initialize Kerberos: {e}")
            return MockKerberosAuth(config.mock_principal)

    logger.warning("Kerberos not configured - using mock authentication")
    return MockKerberosAuth(config.mock_principal)
