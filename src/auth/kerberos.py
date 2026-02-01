"""
HTTP-level Kerberos (SPNEGO/Negotiate) Authentication.

Implements the SPNEGO authentication flow that Windows clients use
when connecting to Kerberos-protected services.

The flow is:
1. Client connects without auth
2. Server responds with 401 + WWW-Authenticate: Negotiate
3. Client sends Authorization: Negotiate <base64-token>
4. Server validates token and extracts client principal
5. Server responds with authentication result (possibly with mutual auth token)
"""

import base64
import logging
from dataclasses import dataclass
from functools import wraps
from typing import Optional, Callable, Tuple

try:
    import gssapi
    from gssapi.raw import sec_contexts
    GSSAPI_AVAILABLE = True
except ImportError:
    GSSAPI_AVAILABLE = False
    gssapi = None

from flask import Request, Response, request, g

logger = logging.getLogger(__name__)


class KerberosError(Exception):
    """Kerberos authentication error."""
    pass


class KerberosConfigError(KerberosError):
    """Kerberos configuration error."""
    pass


class KerberosAuthError(KerberosError):
    """Kerberos authentication failed."""
    pass


@dataclass
class KerberosConfig:
    """Kerberos authentication configuration."""

    # Service principal name (e.g., "HTTP/proxy.example.com@EXAMPLE.COM")
    service_principal: str

    # Path to keytab file containing service credentials
    keytab_path: Optional[str] = None

    # Allow fallback to other auth methods
    allow_fallback: bool = False

    # Require mutual authentication
    mutual_auth: bool = False


class KerberosAuth:
    """
    HTTP-level Kerberos (SPNEGO) authentication handler.

    This implements the server side of the SPNEGO protocol used by
    Windows clients for Kerberos authentication.
    """

    def __init__(self, config: KerberosConfig):
        """
        Initialize Kerberos authentication.

        Args:
            config: Kerberos configuration

        Raises:
            KerberosConfigError: If GSSAPI is not available or config is invalid
        """
        if not GSSAPI_AVAILABLE:
            raise KerberosConfigError(
                "GSSAPI library not available. Install with: pip install gssapi"
            )

        self.config = config
        self._server_creds = None
        self._init_credentials()

    def _init_credentials(self) -> None:
        """Initialize server credentials from keytab."""
        try:
            # Set keytab environment variable if specified
            if self.config.keytab_path:
                import os
                os.environ["KRB5_KTNAME"] = self.config.keytab_path

            # Parse service principal
            # If principal contains '@', use kerberos_principal name type
            # Otherwise use hostbased_service (expects "service@host" format)
            principal = self.config.service_principal
            if "@" in principal and "/" in principal:
                # Full principal like "HTTP/proxy.example.com@REALM"
                service_name = gssapi.Name(
                    principal,
                    name_type=gssapi.NameType.kerberos_principal
                )
            else:
                # Hostbased format like "HTTP@proxy.example.com"
                service_name = gssapi.Name(
                    principal,
                    name_type=gssapi.NameType.hostbased_service
                )

            # Acquire server credentials
            self._server_creds = gssapi.Credentials(
                name=service_name,
                usage="accept"
            )

            logger.info(f"Initialized Kerberos credentials for {self.config.service_principal}")

        except gssapi.exceptions.GSSError as e:
            raise KerberosConfigError(f"Failed to initialize Kerberos credentials: {e}")

    def authenticate(self, auth_header: str) -> Tuple[str, Optional[str]]:
        """
        Authenticate using SPNEGO token from Authorization header.

        Args:
            auth_header: The Authorization header value (e.g., "Negotiate <token>")

        Returns:
            Tuple of (client_principal, response_token)
            - client_principal: The authenticated client's principal name
            - response_token: Optional response token for mutual auth (base64)

        Raises:
            KerberosAuthError: If authentication fails
        """
        if not auth_header.startswith("Negotiate "):
            raise KerberosAuthError("Invalid Authorization header format")

        # Decode the token
        try:
            token_b64 = auth_header[10:]  # Remove "Negotiate " prefix
            token = base64.b64decode(token_b64)
        except Exception as e:
            raise KerberosAuthError(f"Invalid base64 in auth token: {e}")

        # Create security context and process token
        try:
            ctx = gssapi.SecurityContext(creds=self._server_creds, usage="accept")
            response_token = ctx.step(token)

            if not ctx.complete:
                # Multi-step SPNEGO authentication - return token for continuation
                if response_token:
                    response_token_b64 = base64.b64encode(response_token).decode("ascii")
                    # Raise special error that signals need for continuation
                    raise KerberosAuthError(f"CONTINUE:{response_token_b64}")
                else:
                    raise KerberosAuthError("Incomplete GSSAPI context without continuation token")

            # Get client principal name
            client_principal = str(ctx.initiator_name)

            # Prepare response token for mutual auth
            # Always include response token when available; client decides to validate.
            response_token_b64 = None
            if response_token:
                response_token_b64 = base64.b64encode(response_token).decode("ascii")
                if self.config.mutual_auth:
                    logger.debug("Mutual auth token included in response")

            logger.info(f"Kerberos authentication successful for {client_principal}")
            return client_principal, response_token_b64

        except gssapi.exceptions.GSSError as e:
            logger.warning(f"Kerberos authentication failed: {e}")
            raise KerberosAuthError(f"GSSAPI error: {e}")

    def create_challenge_response(self, response_token: str = None) -> Response:
        """
        Create a 401 response with Negotiate challenge.

        Args:
            response_token: Optional token to include in WWW-Authenticate

        Returns:
            Flask Response with 401 status and WWW-Authenticate header
        """
        response = Response(
            "Unauthorized - Kerberos authentication required",
            status=401
        )

        if response_token:
            response.headers["WWW-Authenticate"] = f"Negotiate {response_token}"
        else:
            response.headers["WWW-Authenticate"] = "Negotiate"

        return response


def require_kerberos(kerberos_auth: KerberosAuth):
    """
    Flask decorator to require Kerberos authentication.

    Usage:
        kerberos = KerberosAuth(config)

        @app.route("/protected")
        @require_kerberos(kerberos)
        def protected_endpoint():
            # g.kerberos_principal contains the authenticated user
            return f"Hello {g.kerberos_principal}"
    """
    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def decorated_function(*args, **kwargs):
            auth_header = request.headers.get("Authorization")

            if not auth_header:
                # No auth header - send challenge
                return kerberos_auth.create_challenge_response()

            if not auth_header.startswith("Negotiate"):
                # Wrong auth type
                if kerberos_auth.config.allow_fallback:
                    # Let other auth handlers deal with it
                    g.kerberos_principal = None
                    return f(*args, **kwargs)
                return kerberos_auth.create_challenge_response()

            try:
                principal, response_token = kerberos_auth.authenticate(auth_header)
                g.kerberos_principal = principal

                # Call the actual function
                result = f(*args, **kwargs)

                # Add mutual auth response token if present
                if response_token and isinstance(result, Response):
                    result.headers["WWW-Authenticate"] = f"Negotiate {response_token}"

                return result

            except KerberosAuthError as e:
                error_msg = str(e)
                # Handle multi-step SPNEGO (CONTINUE token)
                if error_msg.startswith("CONTINUE:"):
                    continue_token = error_msg[9:]  # Extract token after "CONTINUE:"
                    logger.debug(f"SPNEGO multi-step: sending CONTINUE token")
                    return kerberos_auth.create_challenge_response(response_token=continue_token)

                logger.warning(f"Kerberos auth failed: {e}")
                return kerberos_auth.create_challenge_response()

        return decorated_function
    return decorator


class MockKerberosAuth:
    """
    Mock Kerberos authentication for development/testing.

    Always authenticates and returns a configurable principal.
    """

    def __init__(self, default_principal: str = "testuser@EXAMPLE.COM"):
        """
        Initialize mock Kerberos auth.

        Args:
            default_principal: Principal to return for all requests
        """
        self.default_principal = default_principal
        self.config = KerberosConfig(
            service_principal="HTTP/localhost@EXAMPLE.COM",
            allow_fallback=True
        )

    def authenticate(self, auth_header: str) -> Tuple[str, Optional[str]]:
        """Always authenticate successfully."""
        return self.default_principal, None

    def create_challenge_response(self, response_token: str = None) -> Response:
        """Create mock challenge response."""
        response = Response("Unauthorized", status=401)
        response.headers["WWW-Authenticate"] = "Negotiate"
        return response


def get_client_principal(request: Request, kerberos_auth: KerberosAuth = None,
                         mock_principal: str = None) -> Optional[str]:
    """
    Get the authenticated client principal from request.

    This is a helper function that can be used outside of Flask decorators.

    Args:
        request: Flask request object
        kerberos_auth: KerberosAuth instance (optional)
        mock_principal: Mock principal for testing (optional)

    Returns:
        Client principal name or None
    """
    # Check if already authenticated (from decorator)
    if hasattr(g, "kerberos_principal") and g.kerberos_principal:
        return g.kerberos_principal

    # Use mock if provided
    if mock_principal:
        return mock_principal

    # Try to authenticate from Authorization header
    if not kerberos_auth:
        return None

    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Negotiate"):
        return None

    try:
        principal, _ = kerberos_auth.authenticate(auth_header)
        return principal
    except KerberosAuthError:
        return None
