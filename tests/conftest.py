"""
Pytest configuration and fixtures.
"""

import os
import pytest
import tempfile


@pytest.fixture
def temp_config_dir():
    """Create a temporary directory for test configurations."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir


@pytest.fixture
def sample_config_file(temp_config_dir):
    """Create a sample configuration file."""
    config_content = """
server:
  host: "127.0.0.1"
  port: 8443
  ssl:
    enabled: false

ejbca:
  url: "https://ejbca.test.local/ejbca"
  client_cert: "/tmp/test-client.crt"
  client_key: "/tmp/test-client.key"
  verify_ssl: false
  default_ca: "TestCA"

active_directory:
  ldap_url: "ldap://dc.test.local"
  base_dn: "DC=test,DC=local"
  use_kerberos: false

kerberos:
  service_principal: "HTTP/proxy.test.local@TEST.LOCAL"

cache:
  enabled: false

logging:
  level: "DEBUG"
  json_format: false

development:
  mock_kerberos: true
  mock_principal: "testuser@TEST.LOCAL"
  debug: true
"""
    config_path = os.path.join(temp_config_dir, "config.yaml")
    with open(config_path, "w") as f:
        f.write(config_content)
    return config_path


@pytest.fixture
def sample_template_mapping(temp_config_dir):
    """Create a sample template mapping file."""
    mapping_content = """
mappings:
  - ad_template: "User"
    ad_template_oid: "1.3.6.1.4.1.311.21.8.1"
    ejbca_ee_profile: "EMPTY"
    ejbca_cert_profile: "ENDUSER"
    ejbca_ca_name: "TestCA"
    auto_enrollment: true
    validity: "1y"
    allowed_groups:
      - "Domain Users"

  - ad_template: "Computer"
    ad_template_oid: "1.3.6.1.4.1.311.21.8.2"
    ejbca_ee_profile: "EMPTY"
    ejbca_cert_profile: "ENDUSER"
    ejbca_ca_name: "TestCA"
    auto_enrollment: true
    validity: "1y"
"""
    mapping_path = os.path.join(temp_config_dir, "template_mapping.yaml")
    with open(mapping_path, "w") as f:
        f.write(mapping_content)
    return mapping_path


@pytest.fixture
def mock_csr():
    """Return a mock PKCS#10 CSR (base64 encoded)."""
    # This is a minimal valid-looking CSR for testing
    # In real tests, you'd generate a proper CSR
    return """
MIICijCCAXICAQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUx
ITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDCCASIwDQYJKoZIhvcN
AQEBBQADggEPADCCAQoCggEBAMF3vL/Uyys2hoHdcefQYjQV/QqFCCnH7dOPwJxM
""".strip().replace("\n", "")


@pytest.fixture
def mock_certificate():
    """Return mock certificate DER bytes."""
    # This would be a real DER-encoded certificate in actual tests
    return b"MOCK_CERTIFICATE_DER_DATA"


@pytest.fixture
def mock_ca_certificate():
    """Return mock CA certificate DER bytes."""
    return b"MOCK_CA_CERTIFICATE_DER_DATA"
