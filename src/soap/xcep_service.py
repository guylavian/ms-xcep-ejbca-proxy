"""
MS-XCEP (X.509 Certificate Enrollment Policy) Service Implementation.

Handles GetPolicies requests from Windows clients and returns certificate
enrollment policies mapped from EJBCA profiles.

Reference: [MS-XCEP] - X.509 Certificate Enrollment Policy Protocol
https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xcep/
"""

import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional
from lxml import etree

from .types import (
    NS, NSMAP, SoapAction, SoapBuilder, SoapParser,
    CertificatePolicy, CAInfo, OID, PolicyResponse,
    serialize_xml, create_nil_element
)

logger = logging.getLogger(__name__)


@dataclass
class GetPoliciesRequest:
    """Parsed GetPolicies request."""

    message_id: str
    last_update: Optional[datetime] = None
    preferred_language: Optional[str] = None
    request_filter: Optional[str] = None


class XCEPService:
    """
    MS-XCEP Certificate Enrollment Policy Service.

    Implements the GetPolicies operation that Windows clients use to
    discover available certificate templates and CAs.
    """

    def __init__(self, policy_provider):
        """
        Initialize XCEP service.

        Args:
            policy_provider: Object that provides certificate policies
                             (maps AD templates to EJBCA profiles)
        """
        self.policy_provider = policy_provider

    def handle_request(self, request_xml: bytes, client_identity: str, 
                        http_soap_action: Optional[str] = None) -> tuple[bytes, str]:
        """
        Handle incoming SOAP request.

        Args:
            request_xml: Raw SOAP request XML
            client_identity: Authenticated client principal (from Kerberos)
            http_soap_action: Optional SOAPAction HTTP header for fallback

        Returns:
            Tuple of (SOAP response XML bytes, groups_hash for caching)
        """
        try:
            envelope = SoapParser.parse(request_xml)
            action = SoapParser.get_action(envelope, http_soap_action)

            if action == SoapAction.XCEP_GET_POLICIES:
                return self._handle_get_policies(envelope, client_identity)
            else:
                logger.warning(f"Unknown SOAP action: {action}")
                return self._create_fault("Sender", f"Unknown action: {action}"), "default"

        except etree.XMLSyntaxError as e:
            logger.error(f"XML parse error: {e}")
            return self._create_fault("Sender", "Invalid XML request"), "default"
        except Exception as e:
            logger.exception(f"Error handling XCEP request: {e}")
            return self._create_fault("Receiver", "Internal server error"), "default"

    def _handle_get_policies(self, envelope: etree._Element,
                             client_identity: str) -> tuple[bytes, str]:
        """Handle GetPolicies request.
        
        Returns:
            Tuple of (SOAP response bytes, groups_hash for caching)
        """
        request = self._parse_get_policies(envelope)
        message_id = SoapParser.get_message_id(envelope)

        logger.info(f"GetPolicies request from {client_identity}, "
                    f"message_id={message_id}")

        # Get policies for this client (returns tuple of policies, groups_hash)
        result = self.policy_provider.get_policies_for_client(client_identity)
        
        # Handle both old (single return) and new (tuple return) signatures
        if isinstance(result, tuple):
            policies, groups_hash = result
        else:
            policies = result
            groups_hash = "default"

        if not policies:
            logger.warning(f"No policies available for {client_identity}")

        # Build response
        response = self._build_get_policies_response(
            policies=policies,
            relates_to=message_id
        )

        return serialize_xml(response), groups_hash

    def _parse_get_policies(self, envelope: etree._Element) -> GetPoliciesRequest:
        """Parse GetPolicies request elements."""
        body = SoapParser.get_body(envelope)
        message_id = SoapParser.get_message_id(envelope)

        get_policies = body.find(f".//{{{NS.XCEP}}}GetPolicies")
        if get_policies is None:
            # Try without namespace for compatibility
            get_policies = body.find(".//GetPolicies")

        last_update = None
        preferred_language = None
        request_filter = None

        if get_policies is not None:
            client = get_policies.find(f"{{{NS.XCEP}}}client")
            if client is None:
                client = get_policies.find("client")

            if client is not None:
                last_update_elem = client.find(f"{{{NS.XCEP}}}lastUpdate")
                if last_update_elem is None:
                    last_update_elem = client.find("lastUpdate")
                if last_update_elem is not None and last_update_elem.text:
                    nil = last_update_elem.get(f"{{{NS.XSI}}}nil")
                    if nil != "true":
                        try:
                            last_update = datetime.fromisoformat(
                                last_update_elem.text.replace("Z", "+00:00")
                            )
                        except ValueError:
                            pass

                lang_elem = client.find(f"{{{NS.XCEP}}}preferredLanguage")
                if lang_elem is None:
                    lang_elem = client.find("preferredLanguage")
                if lang_elem is not None:
                    nil = lang_elem.get(f"{{{NS.XSI}}}nil")
                    if nil != "true":
                        preferred_language = lang_elem.text

            filter_elem = get_policies.find(f"{{{NS.XCEP}}}requestFilter")
            if filter_elem is None:
                filter_elem = get_policies.find("requestFilter")
            if filter_elem is not None:
                nil = filter_elem.get(f"{{{NS.XSI}}}nil")
                if nil != "true":
                    request_filter = filter_elem.text

        return GetPoliciesRequest(
            message_id=message_id,
            last_update=last_update,
            preferred_language=preferred_language,
            request_filter=request_filter
        )

    def _build_get_policies_response(self, policies: PolicyResponse,
                                     relates_to: str = None) -> etree._Element:
        """
        Build GetPoliciesResponse SOAP message.

        Structure per MS-XCEP spec and cepces client expectations:
        - GetPoliciesResponse
          - response
            - policyID
            - policyFriendlyName
            - nextUpdateHours (optional)
            - policiesNotChanged (optional)
            - policies (PolicyCollection)
          - cAs (CACollection) <- at GetPoliciesResponse level, NOT inside response
          - oIDs (OIDCollection) <- at GetPoliciesResponse level, NOT inside response
        
        Note: cepces expects cAs and oIDs as direct children of GetPoliciesResponse,
        not nested inside the response element.
        """
        envelope = SoapBuilder.create_envelope()
        SoapBuilder.add_header(
            envelope,
            action=SoapAction.XCEP_GET_POLICIES_RESPONSE,
            relates_to=relates_to
        )

        body = etree.SubElement(envelope, f"{{{NS.SOAP}}}Body")

        # GetPoliciesResponse element
        gpr = etree.SubElement(body, f"{{{NS.XCEP}}}GetPoliciesResponse")

        # response element
        response = etree.SubElement(gpr, f"{{{NS.XCEP}}}response")

        # Policy ID
        policy_id_elem = etree.SubElement(response, f"{{{NS.XCEP}}}policyID")
        policy_id_elem.text = policies.policy_id if policies else "{00000000-0000-0000-0000-000000000000}"

        # Policy Friendly Name
        friendly_name = etree.SubElement(response, f"{{{NS.XCEP}}}policyFriendlyName")
        friendly_name.text = policies.policy_friendly_name if policies else "Certificate Policy"

        # nextUpdateHours - optional, use integer value or nil
        next_update = etree.SubElement(response, f"{{{NS.XCEP}}}nextUpdateHours")
        if policies and policies.next_update_hours:
            next_update.text = str(policies.next_update_hours)
        else:
            next_update.text = "8"  # Default to 8 hours like AD CS

        # policiesNotChanged - false means we're returning full policies
        policies_not_changed = etree.SubElement(response, f"{{{NS.XCEP}}}policiesNotChanged")
        policies_not_changed.set(f"{{{NS.XSI}}}nil", "true")

        # policies (PolicyCollection) - inside response
        if policies and policies.policies:
            policies_elem = etree.SubElement(response, f"{{{NS.XCEP}}}policies")
            for cert_policy in policies.policies:
                self._add_policy_element(policies_elem, cert_policy)
        else:
            policies_elem = etree.SubElement(response, f"{{{NS.XCEP}}}policies")
            policies_elem.set(f"{{{NS.XSI}}}nil", "true")

        # cAs (CACollection) - at GetPoliciesResponse level per MS-XCEP spec
        if policies and policies.cas:
            cas_elem = etree.SubElement(gpr, f"{{{NS.XCEP}}}cAs")
            for ca in policies.cas:
                self._add_ca_element(cas_elem, ca)
        else:
            cas_elem = etree.SubElement(gpr, f"{{{NS.XCEP}}}cAs")
            cas_elem.set(f"{{{NS.XSI}}}nil", "true")

        # oIDs (OIDCollection) - at GetPoliciesResponse level per MS-XCEP spec
        if policies and policies.oids:
            oids_elem = etree.SubElement(gpr, f"{{{NS.XCEP}}}oIDs")
            for oid in policies.oids:
                self._add_oid_element(oids_elem, oid)
        else:
            oids_elem = etree.SubElement(gpr, f"{{{NS.XCEP}}}oIDs")
            oids_elem.set(f"{{{NS.XSI}}}nil", "true")

        return envelope

    def _add_policy_element(self, parent: etree._Element,
                            policy: CertificatePolicy) -> None:
        """Add a policy element to the policies collection."""
        policy_elem = etree.SubElement(parent, f"{{{NS.XCEP}}}policy")

        # policyOIDReference - links to OID in oIDs collection
        oid_ref = etree.SubElement(policy_elem, f"{{{NS.XCEP}}}policyOIDReference")
        oid_ref.text = policy.policy_oid

        # cAs - CA references for this policy
        cas = etree.SubElement(policy_elem, f"{{{NS.XCEP}}}cAs")
        ca_ref = etree.SubElement(cas, f"{{{NS.XCEP}}}cAReference")
        ca_ref.text = "0"  # Reference to first CA

        # attributes
        attrs = etree.SubElement(policy_elem, f"{{{NS.XCEP}}}attributes")
        self._add_policy_attributes(attrs, policy)

    def _add_policy_attributes(self, parent: etree._Element,
                               policy: CertificatePolicy) -> None:
        """Add certificate policy attributes."""
        # commonName
        cn = etree.SubElement(parent, f"{{{NS.XCEP}}}commonName")
        cn.text = policy.common_name or policy.policy_oid

        # policySchema
        schema = etree.SubElement(parent, f"{{{NS.XCEP}}}policySchema")
        schema.text = "3"  # Schema version

        # certificateValidity
        validity = etree.SubElement(parent, f"{{{NS.XCEP}}}certificateValidity")
        validity_period = etree.SubElement(validity, f"{{{NS.XCEP}}}validityPeriodSeconds")
        validity_period.text = str(policy.certificate_validity.validity_period_seconds)
        renewal_period = etree.SubElement(validity, f"{{{NS.XCEP}}}renewalPeriodSeconds")
        renewal_period.text = str(policy.certificate_validity.renewal_period_seconds)

        # permission
        perm = etree.SubElement(parent, f"{{{NS.XCEP}}}permission")
        enroll = etree.SubElement(perm, f"{{{NS.XCEP}}}enroll")
        enroll.text = "true" if policy.permission_enroll else "false"
        auto_enroll = etree.SubElement(perm, f"{{{NS.XCEP}}}autoEnroll")
        auto_enroll.text = "true" if policy.permission_auto_enroll else "false"

        # privateKeyAttributes
        pk_attrs = etree.SubElement(parent, f"{{{NS.XCEP}}}privateKeyAttributes")
        min_key_len = etree.SubElement(pk_attrs, f"{{{NS.XCEP}}}minimalKeyLength")
        min_key_len.text = str(policy.private_key_attributes.min_key_length)

        key_spec = etree.SubElement(pk_attrs, f"{{{NS.XCEP}}}keySpec")
        key_spec.set(f"{{{NS.XSI}}}nil", "true")

        key_usage = etree.SubElement(pk_attrs, f"{{{NS.XCEP}}}keyUsageProperty")
        key_usage.set(f"{{{NS.XSI}}}nil", "true")

        permissions = etree.SubElement(pk_attrs, f"{{{NS.XCEP}}}permissions")
        permissions.set(f"{{{NS.XSI}}}nil", "true")

        algo_oid = etree.SubElement(pk_attrs, f"{{{NS.XCEP}}}algorithmOIDReference")
        algo_oid.set(f"{{{NS.XSI}}}nil", "true")

        # cryptoProviders - empty for now
        crypto_providers = etree.SubElement(pk_attrs, f"{{{NS.XCEP}}}cryptoProviders")

        # revision
        revision = etree.SubElement(parent, f"{{{NS.XCEP}}}revision")
        major = etree.SubElement(revision, f"{{{NS.XCEP}}}majorRevision")
        major.text = "100"
        minor = etree.SubElement(revision, f"{{{NS.XCEP}}}minorRevision")
        minor.text = "1"

        # supersededPolicies
        superseded = etree.SubElement(parent, f"{{{NS.XCEP}}}supersededPolicies")
        superseded.set(f"{{{NS.XSI}}}nil", "true")

        # privateKeyFlags
        pk_flags = etree.SubElement(parent, f"{{{NS.XCEP}}}privateKeyFlags")
        pk_flags.set(f"{{{NS.XSI}}}nil", "true")

        # subjectNameFlags
        sn_flags = etree.SubElement(parent, f"{{{NS.XCEP}}}subjectNameFlags")
        sn_flags.set(f"{{{NS.XSI}}}nil", "true")

        # enrollmentFlags
        enroll_flags = etree.SubElement(parent, f"{{{NS.XCEP}}}enrollmentFlags")
        enroll_flags.set(f"{{{NS.XSI}}}nil", "true")

        # generalFlags
        general_flags = etree.SubElement(parent, f"{{{NS.XCEP}}}generalFlags")
        general_flags.set(f"{{{NS.XSI}}}nil", "true")

        # hashAlgorithmOIDReference
        hash_algo = etree.SubElement(parent, f"{{{NS.XCEP}}}hashAlgorithmOIDReference")
        hash_algo.text = "0"  # Reference to SHA-256 OID

        # rARequirements
        ra_req = etree.SubElement(parent, f"{{{NS.XCEP}}}rARequirements")
        ra_req.set(f"{{{NS.XSI}}}nil", "true")

        # keyArchivalAttributes
        key_archival = etree.SubElement(parent, f"{{{NS.XCEP}}}keyArchivalAttributes")
        key_archival.set(f"{{{NS.XSI}}}nil", "true")

        # extensions
        extensions = etree.SubElement(parent, f"{{{NS.XCEP}}}extensions")
        extensions.set(f"{{{NS.XSI}}}nil", "true")

    def _add_oid_element(self, parent: etree._Element, oid: OID) -> None:
        """Add an OID element to the OIDs collection."""
        oid_elem = etree.SubElement(parent, f"{{{NS.XCEP}}}oID")

        value = etree.SubElement(oid_elem, f"{{{NS.XCEP}}}value")
        value.text = oid.oid

        group = etree.SubElement(oid_elem, f"{{{NS.XCEP}}}group")
        group.text = str(oid.group)

        oid_ref_id = etree.SubElement(oid_elem, f"{{{NS.XCEP}}}oIDReferenceID")
        oid_ref_id.text = str(oid.reference_id)

        default_name = etree.SubElement(oid_elem, f"{{{NS.XCEP}}}defaultName")
        default_name.text = oid.default_name or oid.name

    def _add_ca_element(self, parent: etree._Element, ca: CAInfo) -> None:
        """Add a CA element to the CAs collection."""
        ca_elem = etree.SubElement(parent, f"{{{NS.XCEP}}}cA")

        # uris
        uris = etree.SubElement(ca_elem, f"{{{NS.XCEP}}}uris")
        uri = etree.SubElement(uris, f"{{{NS.XCEP}}}uri")

        # clientAuthentication - authentication type
        # 1 = Anonymous, 2 = Kerberos, 4 = Username/Password, 8 = Certificate
        client_auth = etree.SubElement(uri, f"{{{NS.XCEP}}}clientAuthentication")
        client_auth.text = "2"  # Kerberos

        uri_elem = etree.SubElement(uri, f"{{{NS.XCEP}}}uri")
        uri_elem.text = ca.ca_uri

        priority = etree.SubElement(uri, f"{{{NS.XCEP}}}priority")
        priority.text = "1"

        renewal_only_elem = etree.SubElement(uri, f"{{{NS.XCEP}}}renewalOnly")
        renewal_only_elem.text = "false"

        # certificate - base64 encoded CA certificate
        cert_elem = etree.SubElement(ca_elem, f"{{{NS.XCEP}}}certificate")
        import base64
        cert_elem.text = base64.b64encode(ca.certificate).decode("ascii")

        # enrollPermission
        enroll_perm = etree.SubElement(ca_elem, f"{{{NS.XCEP}}}enrollPermission")
        enroll_perm.text = "true"

        # cAReferenceID
        ca_ref_id = etree.SubElement(ca_elem, f"{{{NS.XCEP}}}cAReferenceID")
        ca_ref_id.text = str(ca.ca_reference)

    def _create_fault(self, code: str, reason: str) -> bytes:
        """Create SOAP fault response."""
        fault = SoapBuilder.create_soap_fault(code, reason)
        return serialize_xml(fault)
