"""
Health check endpoints Blueprint.

Provides Kubernetes-compatible liveness and readiness probes.
"""

import os

from flask import Blueprint, current_app

health_bp = Blueprint("health", __name__)


@health_bp.route("/health")
def health():
    """Basic health check endpoint (liveness)."""
    return {"status": "ok"}, 200


@health_bp.route("/healthz")
def healthz():
    """Kubernetes liveness probe."""
    return {"status": "ok"}, 200


@health_bp.route("/readyz")
def readyz():
    """
    Kubernetes readiness probe.

    Checks that backend dependencies (EJBCA, LDAP, cache, keytab) are reachable.
    """
    ejbca_client = current_app.config.get("EJBCA_CLIENT")
    ldap_client = current_app.config.get("LDAP_CLIENT")
    cache = current_app.config.get("CACHE")
    config = current_app.config.get("XCEP_CONFIG")

    checks = {}
    ready = True

    # EJBCA reachable
    if ejbca_client:
        try:
            checks["ejbca"] = ejbca_client.health_check()
        except Exception:
            checks["ejbca"] = False
    else:
        checks["ejbca"] = False
    ready = ready and checks["ejbca"]

    # LDAP reachable (optional)
    if ldap_client:
        try:
            checks["ldap"] = ldap_client.is_connected()
        except Exception:
            checks["ldap"] = False
    else:
        checks["ldap"] = None  # not configured

    # Cache available (optional)
    if cache:
        checks["cache"] = cache.available
    else:
        checks["cache"] = None

    # Kerberos keytab readable
    if config and config.kerberos_keytab:
        checks["keytab"] = os.path.isfile(config.kerberos_keytab)
        ready = ready and checks["keytab"]
    else:
        checks["keytab"] = None

    status_code = 200 if ready else 503
    return {"ready": ready, "checks": checks}, status_code
