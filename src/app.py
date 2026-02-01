"""
Flask Application Factory.

Creates and configures the Flask application with all dependencies wired up.
This is a thin factory - business logic lives in services, not here.
"""

import os
from typing import Optional

from flask import Flask, g, request

from .api import health_bp, xcep_bp, wstep_bp
from .config import AppConfig, load_config
from .services import create_services
from .utils.logging import configure_logging, get_logger, AuditLogger

logger = get_logger(__name__)


def create_app(config_path: Optional[str] = None) -> Flask:
    """
    Create and configure the Flask application.

    Args:
        config_path: Path to configuration file (defaults to XCEP_CONFIG env var)

    Returns:
        Configured Flask application
    """
    app = Flask(__name__)

    # Load configuration
    if config_path is None:
        config_path = os.environ.get("XCEP_CONFIG", "config/config.yaml")

    try:
        config = load_config(config_path)
    except FileNotFoundError:
        logger.warning(f"Config file not found: {config_path}, using defaults")
        config = AppConfig()

    app.config["XCEP_CONFIG"] = config

    # Configure logging
    configure_logging(
        level=config.log_level,
        json_format=config.log_json,
        log_file=config.log_file
    )

    # Initialize shared audit logger
    app.config["AUDIT_LOGGER"] = AuditLogger()

    # Create all services (CA client, LDAP client, cache, etc.)
    services = create_services(config)

    # Store services in app config
    app.config["CACHE"] = services.cache
    app.config["EJBCA_CLIENT"] = services.ca_client
    app.config["LDAP_CLIENT"] = services.ldap_client
    app.config["TEMPLATE_MANAGER"] = services.template_manager
    app.config["POLICY_PROVIDER"] = services.policy_provider
    app.config["XCEP_SERVICE"] = services.xcep_service
    app.config["ENROLLMENT_HANDLER"] = services.enrollment_handler
    app.config["WSTEP_SERVICE"] = services.wstep_service
    app.config["KERBEROS_AUTH"] = services.kerberos_auth

    # Register request hooks
    _register_hooks(app)

    # Register blueprints
    app.register_blueprint(health_bp)
    app.register_blueprint(xcep_bp)
    app.register_blueprint(wstep_bp)

    logger.info("Application initialized successfully")
    return app


def _register_hooks(app: Flask) -> None:
    """Register before/after request hooks."""

    @app.before_request
    def authenticate():
        """Authenticate all requests using Kerberos."""
        kerberos_auth = app.config["KERBEROS_AUTH"]

        # Skip auth for health check endpoints
        if request.path in ("/health", "/healthz", "/readyz"):
            return

        auth_header = request.headers.get("Authorization")

        if not auth_header:
            return kerberos_auth.create_challenge_response()

        if auth_header.startswith("Negotiate"):
            try:
                principal, response_token = kerberos_auth.authenticate(auth_header)
                g.client_identity = principal
                g.auth_response_token = response_token

                # Fetch user groups ONCE per request
                _fetch_user_groups(app, principal)

            except Exception as e:
                error_msg = str(e)
                # Handle SPNEGO multi-step (CONTINUE token)
                if error_msg.startswith("CONTINUE:"):
                    continue_token = error_msg[9:]
                    logger.debug("SPNEGO multi-step: sending CONTINUE token")
                    return kerberos_auth.create_challenge_response(response_token=continue_token)
                logger.warning(f"Kerberos auth failed: {e}")
                return kerberos_auth.create_challenge_response()
        else:
            return kerberos_auth.create_challenge_response()

    @app.after_request
    def add_auth_header(response):
        """Add mutual auth response token if present."""
        if hasattr(g, "auth_response_token") and g.auth_response_token:
            response.headers["WWW-Authenticate"] = f"Negotiate {g.auth_response_token}"
        return response


def _fetch_user_groups(app: Flask, principal: str) -> None:
    """
    Fetch user groups from LDAP and store in request context.

    Args:
        app: Flask application
        principal: Kerberos principal
    """
    import hashlib

    ldap_client = app.config.get("LDAP_CLIENT")
    if not ldap_client:
        g.user_groups = None
        g.groups_hash = "no_ldap"
        return

    try:
        # Try as user first
        user_info = ldap_client.get_user_by_principal(principal)
        if user_info:
            g.user_groups = user_info.get("groups", [])
        else:
            # Try as computer account
            computer_name = principal.split("@")[0] if "@" in principal else principal
            computer_info = ldap_client.get_computer_by_name(computer_name)
            if computer_info:
                g.user_groups = computer_info.get("groups", [])
            else:
                g.user_groups = []

        # Compute stable hash for cache key
        sorted_groups = sorted(grp.lower() for grp in g.user_groups)
        groups_str = "|".join(sorted_groups)
        g.groups_hash = hashlib.sha256(groups_str.encode("utf-8")).hexdigest()[:16]

    except Exception as e:
        logger.warning(f"LDAP groups lookup failed for {principal}: {e}")
        g.user_groups = None
        g.groups_hash = "ldap_error"


def create_wsgi_app() -> Flask:
    """Create WSGI application for gunicorn."""
    config_path = os.environ.get("XCEP_CONFIG", "config/config.yaml")
    return create_app(config_path)
