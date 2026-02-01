# MS-XCEP/WSTEP to EJBCA Proxy Server

A Python proxy server that implements Microsoft's MS-XCEP (Certificate Enrollment Policy) and MS-WSTEP (Certificate Enrollment) protocols to enable Windows certificate autoenrollment against EJBCA instead of Microsoft AD CS.

## Features

- **MS-XCEP Protocol**: Handles GetPolicies requests from Windows clients
- **MS-WSTEP Protocol**: Handles RequestSecurityToken for certificate enrollment
- **EJBCA Integration**: Translates SOAP requests to EJBCA REST API calls
- **Kerberos Authentication**: HTTP-level SPNEGO/Negotiate authentication
- **AD Integration**: Reads certificate templates from Active Directory
- **Template Mapping**: Maps AD templates to EJBCA profiles
- **Redis Caching**: Caches policy responses for performance
- **Structured Logging**: JSON logging for SIEM integration
- **Audit Trail**: Comprehensive logging of enrollment events

## Architecture

```
┌─────────────────┐     SOAP/HTTPS      ┌──────────────────┐     REST/HTTPS     ┌─────────┐
│  Windows Client │ ─────────────────>  │   Python Proxy   │ ────────────────>  │  EJBCA  │
│  (Autoenroll)   │ <─────────────────  │  (Flask/lxml)    │ <────────────────  │   CA    │
└─────────────────┘                     └──────────────────┘                    └─────────┘
                                               │
                                               │ LDAP
                                               ▼
                                        ┌──────────────┐
                                        │ Active       │
                                        │ Directory    │
                                        └──────────────┘
```

## Quick Start

### Prerequisites

- Python 3.10+
- EJBCA with REST API enabled
- Active Directory (optional, for template discovery)
- Redis (optional, for caching)
- Kerberos keytab for the service

### Installation

```bash
# Clone the repository
cd /Users/guylavian/dev/ms-xcep-ejbca-proxy

# Create virtual environment
python -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Configuration

1. Copy and edit the configuration file:
```bash
cp config/config.yaml config/config.local.yaml
# Edit config/config.local.yaml with your settings
```

2. Configure template mappings:
```bash
# Edit config/template_mapping.yaml
```

3. Set up certificates:
```bash
mkdir -p certs
# Place your server certificate, key, and EJBCA client certificate
```

### Running the Server

#### Development Mode
```bash
# With mock Kerberos (for testing)
python -m src.main -c config/config.local.yaml -d
```

#### Production Mode
```bash
# Using gunicorn
gunicorn \
    --bind 0.0.0.0:443 \
    --workers 4 \
    --keyfile certs/server.key \
    --certfile certs/server.crt \
    "src.main:create_wsgi_app()"
```

#### Docker
```bash
# Build and run
docker-compose up -d
```

## Configuration Reference

### Server Configuration

```yaml
server:
  host: "0.0.0.0"
  port: 443
  ssl:
    enabled: true
    cert_file: "/etc/proxy/server.crt"
    key_file: "/etc/proxy/server.key"
  workers: 4
```

### EJBCA Configuration

```yaml
ejbca:
  url: "https://ejbca.example.com/ejbca"
  client_cert: "/etc/proxy/ejbca-client.crt"
  client_key: "/etc/proxy/ejbca-client.key"
  default_ca: "MyCA"
  default_end_entity_profile: "EMPTY"
  default_cert_profile: "ENDUSER"
```

### EJBCA Profile Requirements

For the proxy to work correctly, EJBCA must be configured with matching profiles:

#### End Entity Profile Requirements
- **Subject DN**: Must allow the DN pattern from the CSR (e.g., `CN=*`)
- **Subject DN validation**: Set to "Use subject DN from CSR" or allow override
- **Key algorithms**: Must match what Windows clients send (typically RSA 2048/4096)
- **Certificate profiles**: Must list the certificate profile used in the mapping

#### Certificate Profile Requirements
- **Key Usage**: Match the intended use (digitalSignature, keyEncipherment, etc.)
- **Extended Key Usage**: Include required EKUs based on template type:
  - User: `clientAuth`, `emailProtection`
  - Computer: `clientAuth`, `serverAuth`
  - WebServer: `serverAuth`
  - CodeSigning: `codeSigning`
- **Subject Alternative Names**: Allow SAN from CSR if clients include it
- **Validity**: Sufficient for the template's validity period

#### CA Requirements
- CA must be in **active state**
- CA must have sufficient validity to issue certificates
- CA must be listed in the certificate profile's available CAs

#### REST API Authentication
- The mTLS client certificate used by the proxy must have an admin role with:
  - `ca_functionality`: To access CA information
  - `endentity`: To create/modify end entities
  - `ra_functionality`: To issue certificates

### Kerberos Configuration

```yaml
kerberos:
  service_principal: "HTTP/proxy.example.com@EXAMPLE.COM"
  keytab: "/etc/proxy/proxy.keytab"
```

### Template Mapping

```yaml
mappings:
  - ad_template: "User"
    ad_template_oid: "1.3.6.1.4.1.311.21.8.XXXXX"  # Real OID from AD (msPKI-Cert-Template-OID)
    ejbca_ee_profile: "UserEndEntityProfile"
    ejbca_cert_profile: "UserCertProfile"
    ejbca_ca_name: "MyCA"
    auto_enrollment: true
    validity: "1y"
    allowed_groups:
      - "Domain Users"
```

**Important**: The `ad_template_oid` should be the real OID from Active Directory. You can find it using:
```powershell
# PowerShell - get template OIDs from AD
Get-ADObject -SearchBase "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=example,DC=com" -Filter {objectClass -eq "pKICertificateTemplate"} -Properties msPKI-Cert-Template-OID | Select Name, msPKI-Cert-Template-OID
```

If the OID doesn't match what Windows expects, clients may fail to select or enroll for the correct template.

## Windows Client Configuration

### Group Policy Configuration

1. Open Group Policy Management
2. Navigate to: Computer Configuration → Policies → Windows Settings → Security Settings → Public Key Policies
3. Right-click "Certificate Services Client - Certificate Enrollment Policy" and create a new policy
4. Enter the proxy URL: `https://proxy.example.com/ADPolicyProvider_CEP_Kerberos/service.svc/CEP`
5. Select "Windows Integrated" authentication

### Testing

```powershell
# Test connectivity
certutil -ping -kerberos https://proxy.example.com/ADPolicyProvider_CEP_Kerberos/service.svc/CEP

# Force certificate enrollment
certutil -pulse
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/ADPolicyProvider_CEP_Kerberos/service.svc/CEP` | POST | MS-XCEP GetPolicies |
| `/ADPolicyProvider_CES_Kerberos/service.svc/CES` | POST | MS-WSTEP RequestSecurityToken |
| `/health` | GET | Health check |

## Development

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src --cov-report=html

# Run specific test file
pytest tests/test_xcep.py -v
```

### Project Structure

```
ms-xcep-ejbca-proxy/
├── config/
│   ├── config.yaml           # Main configuration
│   └── template_mapping.yaml # AD template to EJBCA profile mapping
├── src/
│   ├── main.py              # Application entry point
│   ├── enrollment_handler.py # Enrollment processing
│   ├── soap/                # SOAP protocol implementation
│   ├── ejbca/               # EJBCA REST client
│   ├── ad/                  # AD LDAP integration
│   ├── auth/                # Kerberos authentication
│   ├── cache/               # Redis caching
│   └── utils/               # Utilities
├── tests/                   # Test suite
├── Dockerfile
└── docker-compose.yaml
```

## Troubleshooting

### Common Issues

1. **Kerberos authentication fails**
   - Verify keytab is correctly generated
   - Check SPN matches server certificate
   - Ensure time sync between client and server

2. **EJBCA returns 400 Bad Request**
   - Verify end entity profile allows the requested DN
   - Check certificate profile settings
   - Ensure CA is in active state

3. **Windows client doesn't see templates**
   - Check policy response structure
   - Verify template OIDs match
   - Test with certutil -ping

### Debug Mode

Enable debug logging:
```yaml
logging:
  level: "DEBUG"
development:
  debug: true
```

## Security Considerations

- Always use HTTPS in production
- Protect the EJBCA client certificate
- Use strong keytab permissions (600)
- Enable structured logging for SIEM
- Implement rate limiting for production
- Regular key rotation

## License

MIT License
