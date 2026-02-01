"""
Application configuration using dataclasses.

Provides type-safe configuration loading from YAML files.
"""

from dataclasses import dataclass
from typing import Optional

import yaml


@dataclass
class ServerConfig:
    """Server configuration."""
    host: str = "0.0.0.0"
    port: int = 443
    public_fqdn: str = ""
    ssl_cert: Optional[str] = None
    ssl_key: Optional[str] = None
    workers: int = 4


@dataclass
class EJBCAConfig:
    """EJBCA CA backend configuration."""
    url: str = ""
    client_cert: str = ""
    client_key: str = ""
    ca_cert: Optional[str] = None
    verify_ssl: bool = True
    default_ca: str = "MyCA"
    default_ee_profile: str = "EMPTY"
    default_cert_profile: str = "ENDUSER"


@dataclass
class LDAPConfig:
    """Active Directory LDAP configuration."""
    url: str = ""
    base_dn: str = ""
    use_kerberos: bool = True
    username: Optional[str] = None
    password: Optional[str] = None


@dataclass
class KerberosConfig:
    """Kerberos authentication configuration."""
    service_principal: str = ""
    keytab: Optional[str] = None
    allow_fallback: bool = False


@dataclass
class CacheConfig:
    """Cache configuration."""
    enabled: bool = True
    host: str = "localhost"
    port: int = 6379
    ttl: int = 300


@dataclass
class LoggingConfig:
    """Logging configuration."""
    level: str = "INFO"
    json_format: bool = False
    file: Optional[str] = None


@dataclass
class DevelopmentConfig:
    """Development mode configuration."""
    mock_kerberos: bool = False
    mock_principal: str = "testuser@EXAMPLE.COM"
    debug: bool = False


@dataclass
class AppConfig:
    """
    Complete application configuration.

    All settings with sensible defaults that can be overridden via YAML config file.
    """
    # Server settings
    host: str = "0.0.0.0"
    port: int = 443
    public_fqdn: str = ""
    ssl_cert: Optional[str] = None
    ssl_key: Optional[str] = None
    workers: int = 4

    # EJBCA settings
    ejbca_url: str = ""
    ejbca_client_cert: str = ""
    ejbca_client_key: str = ""
    ejbca_ca_cert: Optional[str] = None
    ejbca_verify_ssl: bool = True
    ejbca_default_ca: str = "MyCA"
    ejbca_default_ee_profile: str = "EMPTY"
    ejbca_default_cert_profile: str = "ENDUSER"

    # AD settings
    ldap_url: str = ""
    ldap_base_dn: str = ""
    ldap_use_kerberos: bool = True
    ldap_username: Optional[str] = None
    ldap_password: Optional[str] = None

    # Kerberos settings
    kerberos_principal: str = ""
    kerberos_keytab: Optional[str] = None
    kerberos_allow_fallback: bool = False

    # Cache settings
    cache_enabled: bool = True
    cache_host: str = "localhost"
    cache_port: int = 6379

    # Logging
    log_level: str = "INFO"
    log_json: bool = False
    log_file: Optional[str] = None

    # Template mapping
    template_mapping_file: str = ""

    # Development
    mock_kerberos: bool = False
    mock_principal: str = "testuser@EXAMPLE.COM"
    debug: bool = False


def load_config(config_path: str) -> AppConfig:
    """
    Load configuration from YAML file.

    Args:
        config_path: Path to YAML configuration file

    Returns:
        Populated AppConfig instance

    Raises:
        FileNotFoundError: If config file doesn't exist
    """
    with open(config_path) as f:
        data = yaml.safe_load(f)

    config = AppConfig()

    # Server settings
    server = data.get("server", {})
    config.host = server.get("host", config.host)
    config.port = server.get("port", config.port)
    config.public_fqdn = server.get("public_fqdn", server.get("host", config.host))
    ssl = server.get("ssl", {})
    if ssl.get("enabled", False):
        config.ssl_cert = ssl.get("cert_file")
        config.ssl_key = ssl.get("key_file")
    config.workers = server.get("workers", config.workers)

    # EJBCA settings
    ejbca = data.get("ejbca", {})
    config.ejbca_url = ejbca.get("url", "")
    config.ejbca_client_cert = ejbca.get("client_cert", "")
    config.ejbca_client_key = ejbca.get("client_key", "")
    config.ejbca_ca_cert = ejbca.get("ca_cert")
    config.ejbca_verify_ssl = ejbca.get("verify_ssl", True)
    config.ejbca_default_ca = ejbca.get("default_ca", "MyCA")
    config.ejbca_default_ee_profile = ejbca.get("default_end_entity_profile", "EMPTY")
    config.ejbca_default_cert_profile = ejbca.get("default_cert_profile", "ENDUSER")

    # AD settings
    ad = data.get("active_directory", {})
    config.ldap_url = ad.get("ldap_url", "")
    config.ldap_base_dn = ad.get("base_dn", "")
    config.ldap_use_kerberos = ad.get("use_kerberos", True)
    config.ldap_username = ad.get("username")
    config.ldap_password = ad.get("password")

    # Kerberos settings
    krb = data.get("kerberos", {})
    config.kerberos_principal = krb.get("service_principal", "")
    config.kerberos_keytab = krb.get("keytab")
    config.kerberos_allow_fallback = krb.get("allow_fallback", False)

    # Cache settings
    cache = data.get("cache", {})
    config.cache_enabled = cache.get("enabled", True)
    config.cache_host = cache.get("host", "localhost")
    config.cache_port = cache.get("port", 6379)

    # Logging
    log = data.get("logging", {})
    config.log_level = log.get("level", "INFO")
    config.log_json = log.get("json_format", False)
    config.log_file = log.get("file")

    # Template mapping
    config.template_mapping_file = data.get("template_mapping_file", "")

    # Development
    dev = data.get("development", {})
    config.mock_kerberos = dev.get("mock_kerberos", False)
    config.mock_principal = dev.get("mock_principal", "testuser@EXAMPLE.COM")
    config.debug = dev.get("debug", False)

    return config
