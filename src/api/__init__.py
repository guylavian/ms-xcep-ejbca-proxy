"""
API Blueprints for MS-XCEP/WSTEP proxy.

This package contains Flask Blueprints that define the HTTP endpoints
for the proxy server:
- health: Health check endpoints (liveness/readiness probes)
- xcep: MS-XCEP Certificate Enrollment Policy endpoints
- wstep: MS-WSTEP Certificate Enrollment Service endpoints
"""

from .health import health_bp
from .xcep import xcep_bp
from .wstep import wstep_bp

__all__ = ["health_bp", "xcep_bp", "wstep_bp"]
