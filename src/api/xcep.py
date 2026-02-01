"""
MS-XCEP (Certificate Enrollment Policy) Blueprint.

Handles GetPolicies SOAP requests from Windows clients.
"""

from typing import Optional

from flask import Blueprint, current_app, g, request, Response

from ..utils.logging import get_logger

logger = get_logger(__name__)

xcep_bp = Blueprint("xcep", __name__)


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
        # Parse action from: application/soap+xml; action="uri"
        for part in content_type.split(";"):
            part = part.strip()
            if part.startswith("action="):
                return part[7:].strip().strip('"')

    return None


def _count_policies_in_response(response_xml: bytes) -> int:
    """
    Count the number of policies in an XCEP response.

    Args:
        response_xml: SOAP response XML bytes

    Returns:
        Number of policy elements found, or -1 on error
    """
    try:
        from lxml import etree
        root = etree.fromstring(response_xml)
        NS_XCEP = "http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy"
        policies = root.findall(f".//{{{NS_XCEP}}}policy")
        return len(policies)
    except Exception:
        return -1


@xcep_bp.route("/ADPolicyProvider_CEP_Kerberos/service.svc/CEP", methods=["POST"])
@xcep_bp.route("/ADPolicyProvider_cep_kerberos/service.svc/cep", methods=["POST"])
def xcep_endpoint():
    """Handle MS-XCEP GetPolicies requests."""
    xcep_service = current_app.config["XCEP_SERVICE"]
    cache = current_app.config.get("CACHE")
    audit_logger = current_app.config.get("AUDIT_LOGGER")

    client_identity = getattr(g, "client_identity", "anonymous")

    # Use groups_hash from before_request (already fetched once)
    groups_hash = getattr(g, "groups_hash", "default")

    # Check cache with groups_hash
    if cache and cache.available:
        cached_response = cache.get_policy_response(client_identity, groups_hash)
        if cached_response:
            logger.debug(f"Cache hit for policy response: {client_identity} (groups_hash={groups_hash})")
            return Response(
                cached_response,
                mimetype="application/soap+xml; charset=utf-8"
            )

    # Process request
    http_soap_action = _get_soap_action()
    result = xcep_service.handle_request(
        request.data,
        client_identity,
        http_soap_action
    )

    # Handle both old (bytes) and new (tuple) return signatures
    if isinstance(result, tuple):
        response_xml, returned_groups_hash = result
        # Always prefer the hash from xcep_service if it's valid
        if returned_groups_hash and returned_groups_hash not in ("default", ""):
            groups_hash = returned_groups_hash
    else:
        response_xml = result

    # Cache response with groups_hash
    if cache and cache.available:
        cache.set_policy_response(client_identity, response_xml, groups_hash)

    # Count actual policies returned (from XML response)
    policies_count = _count_policies_in_response(response_xml)

    # Audit log
    if audit_logger:
        audit_logger.log_policy_request(
            client_identity=client_identity,
            client_ip=request.remote_addr,
            policies_returned=policies_count
        )

    return Response(
        response_xml,
        mimetype="application/soap+xml; charset=utf-8"
    )


@xcep_bp.route("/ADPolicyProvider_CEP_Kerberos/service.svc", methods=["GET"])
def xcep_wsdl():
    """Return XCEP WSDL (placeholder)."""
    return Response(
        "<!-- WSDL not implemented - use ?wsdl for proper WSDL -->",
        mimetype="text/xml"
    )
