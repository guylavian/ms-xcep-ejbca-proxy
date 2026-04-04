"""
MS-XCEP/WSTEP to EJBCA Proxy Server - Main Entry Point.

This is a Flask application that implements MS-XCEP and MS-WSTEP
protocols for Windows certificate autoenrollment, translating
requests to EJBCA's REST API.

Production deployment:
    Use gunicorn (or another WSGI server) behind a reverse proxy (nginx):
        gunicorn -w 4 -b 0.0.0.0:8443 'src.main:create_wsgi_app()'
    Do NOT use app.run() for production.

NOTE: This module is kept for backward compatibility.
      New code should use src.app.create_app() instead.
"""

from .app import create_app, create_wsgi_app
# Re-export from new locations for backward compatibility
from .config import AppConfig, load_config
from .utils.logging import get_logger

logger = get_logger(__name__)

# Re-export for backward compatibility
__all__ = [
    "AppConfig",
    "load_config",
    "create_app",
    "create_wsgi_app",
]

# Development server
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="MS-XCEP/WSTEP to EJBCA Proxy")
    parser.add_argument("-c", "--config", default="config/config.yaml",
                        help="Path to configuration file")
    parser.add_argument("-d", "--debug", action="store_true",
                        help="Enable debug mode")
    args = parser.parse_args()

    app = create_app(args.config)
    config = app.config["XCEP_CONFIG"]

    ssl_context = None
    if config.ssl_cert and config.ssl_key:
        ssl_context = (config.ssl_cert, config.ssl_key)

    app.run(
        host=config.host,
        port=config.port,
        debug=args.debug or config.debug,
        ssl_context=ssl_context
    )
