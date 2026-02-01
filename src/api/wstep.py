"""
MS-WSTEP (Certificate Enrollment Service) Blueprint.

Handles RequestSecurityToken SOAP requests from Windows clients.
"""

from typing import Optional

from flask import Blueprint, current_app, g, request, Response

from ..soap.types import SoapBuilder, serialize_xml
from ..utils.logging import get_logger

logger = get_logger(__name__)

wstep_bp = Blueprint("wstep", __name__)


def _get_soap_action() -> Optional[str]:
    """
    Get SOAPAction from HTTP headers.

    SOAPAction can be in:
    - SOAPAction header (SOAP 1.1)
    - Content-Type action parameter (SOAP 1.2)
    """
    # Check SOAPAction header (SOAP 1.1)
    soap_action = request.headers.get("SOAPAction")
    if soap_action:
        return soap_action.strip().strip('"')

    # Check Content-Type action parameter (SOAP 1.2)
    content_type = request.headers.get("Content-Type", "")
    if "action=" in content_type:
        for part in content_type.split(";"):
            part = part.strip()
            if part.startswith("action="):
                return part[7:].strip().strip('"')

    return None


def _get_client_ip() -> str:
    """Get client IP from X-Forwarded-For header or remote_addr."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        # Take the first IP in the list (original client)
        return forwarded.split(",")[0].strip()
    return request.remote_addr or ""


@wstep_bp.route("/ADPolicyProvider_CES_Kerberos/service.svc/CES", methods=["POST"])
@wstep_bp.route("/ADPolicyProvider_ces_kerberos/service.svc/ces", methods=["POST"])
def wstep_endpoint():
    """Handle MS-WSTEP RequestSecurityToken requests."""
    wstep_service = current_app.config["WSTEP_SERVICE"]
    enrollment_handler = current_app.config.get("ENROLLMENT_HANDLER")

    if not enrollment_handler:
        # Return SOAP fault if EJBCA not configured
        fault = SoapBuilder.create_soap_fault(
            "Receiver",
            "Certificate enrollment service not configured"
        )
        return Response(
            serialize_xml(fault),
            status=500,
            mimetype="application/soap+xml; charset=utf-8"
        )

    client_identity = getattr(g, "client_identity", "anonymous")
    client_ip = _get_client_ip()
    http_soap_action = _get_soap_action()

    response_xml = wstep_service.handle_request(
        request.data,
        client_identity,
        client_ip,
        http_soap_action
    )

    return Response(
        response_xml,
        mimetype="application/soap+xml; charset=utf-8"
    )


@wstep_bp.route("/ADPolicyProvider_CES_Kerberos/service.svc", methods=["GET"])
def wstep_wsdl():
    """Return WSTEP WSDL (placeholder)."""
    return Response(
        "<!-- WSDL not implemented - use ?wsdl for proper WSDL -->",
        mimetype="text/xml"
    )
