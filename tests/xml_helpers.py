"""
XML test helpers for conformance testing.

Provides canonicalization, comparison, and validation utilities
for MS-XCEP and MS-WSTEP XML messages.
"""

import re
from io import BytesIO
from typing import Optional
from lxml import etree
from lxml.etree import _Element

from src.soap.types import NS


def canonicalize_xml(xml_bytes: bytes, remove_timestamps: bool = True,
                     remove_ids: bool = True) -> bytes:
    """
    Canonicalize XML for comparison.

    Uses Exclusive XML Canonicalization (exc-c14n) to normalize:
    - Namespace declarations
    - Attribute ordering
    - Whitespace in tags

    Args:
        xml_bytes: Raw XML bytes
        remove_timestamps: Remove timestamp elements that vary
        remove_ids: Remove random IDs (MessageID, RequestID, etc.)

    Returns:
        Canonicalized XML bytes
    """
    tree = etree.parse(BytesIO(xml_bytes))
    root = tree.getroot()

    if remove_timestamps:
        _remove_elements(root, [
            f".//{{{NS.WSU}}}Timestamp",
            f".//{{{NS.WSU}}}Created",
            f".//{{{NS.WSU}}}Expires",
        ])

    if remove_ids:
        _remove_elements(root, [
            f".//{{{NS.WSA}}}MessageID",
            f".//{{{NS.WSA}}}RelatesTo",
        ])
        # Also remove wsu:Id attributes
        for elem in root.iter():
            if f"{{{NS.WSU}}}Id" in elem.attrib:
                del elem.attrib[f"{{{NS.WSU}}}Id"]

    # Use exclusive canonicalization
    return etree.tostring(root, method="c14n", exclusive=True)


def _remove_elements(root: _Element, xpaths: list) -> None:
    """Remove elements matching XPath expressions."""
    for xpath in xpaths:
        for elem in root.findall(xpath):
            parent = elem.getparent()
            if parent is not None:
                parent.remove(elem)


def compare_xml_structure(actual: bytes, expected: bytes,
                          ignore_values: bool = False) -> tuple:
    """
    Compare XML structure between actual and expected.

    Args:
        actual: Actual XML bytes
        expected: Expected XML bytes
        ignore_values: If True, only compare element names/structure

    Returns:
        Tuple of (is_equal: bool, differences: list[str])
    """
    actual_tree = etree.parse(BytesIO(actual))
    expected_tree = etree.parse(BytesIO(expected))

    differences = []
    _compare_elements(actual_tree.getroot(), expected_tree.getroot(),
                      differences, ignore_values, path="")

    return len(differences) == 0, differences


def _compare_elements(actual: _Element, expected: _Element,
                      differences: list, ignore_values: bool, path: str) -> None:
    """Recursively compare XML elements."""
    current_path = f"{path}/{actual.tag}" if path else actual.tag

    # Compare tag names
    if actual.tag != expected.tag:
        differences.append(f"Tag mismatch at {path}: {actual.tag} != {expected.tag}")
        return

    # Compare text content (if not ignoring values)
    if not ignore_values:
        actual_text = (actual.text or "").strip()
        expected_text = (expected.text or "").strip()
        if actual_text != expected_text:
            differences.append(f"Text mismatch at {current_path}: '{actual_text}' != '{expected_text}'")

    # Compare attributes
    actual_attrs = set(actual.attrib.keys())
    expected_attrs = set(expected.attrib.keys())

    missing_attrs = expected_attrs - actual_attrs
    extra_attrs = actual_attrs - expected_attrs

    if missing_attrs:
        differences.append(f"Missing attributes at {current_path}: {missing_attrs}")
    if extra_attrs:
        differences.append(f"Extra attributes at {current_path}: {extra_attrs}")

    if not ignore_values:
        for attr in actual_attrs & expected_attrs:
            if actual.attrib[attr] != expected.attrib[attr]:
                differences.append(
                    f"Attribute '{attr}' mismatch at {current_path}: "
                    f"'{actual.attrib[attr]}' != '{expected.attrib[attr]}'"
                )

    # Compare children
    actual_children = list(actual)
    expected_children = list(expected)

    if len(actual_children) != len(expected_children):
        differences.append(
            f"Child count mismatch at {current_path}: "
            f"{len(actual_children)} != {len(expected_children)}"
        )

    # Compare each child
    for i, (actual_child, expected_child) in enumerate(
            zip(actual_children, expected_children)
    ):
        _compare_elements(actual_child, expected_child, differences,
                          ignore_values, current_path)


def extract_namespaces(xml_bytes: bytes) -> dict:
    """
    Extract all namespace declarations from XML.

    Returns:
        Dict mapping prefix to namespace URI
    """
    tree = etree.parse(BytesIO(xml_bytes))
    root = tree.getroot()

    namespaces = {}
    for elem in root.iter():
        namespaces.update(elem.nsmap)

    return namespaces


def validate_soap_envelope(xml_bytes: bytes) -> tuple:
    """
    Validate basic SOAP 1.2 envelope structure.

    Returns:
        Tuple of (is_valid: bool, errors: list[str])
    """
    errors = []

    try:
        tree = etree.parse(BytesIO(xml_bytes))
        root = tree.getroot()
    except etree.XMLSyntaxError as e:
        return False, [f"XML parse error: {e}"]

    # Check root element
    if root.tag not in (f"{{{NS.SOAP}}}Envelope", f"{{{NS.SOAP11}}}Envelope"):
        errors.append(f"Root element is not SOAP Envelope: {root.tag}")

    # Check for Header and Body
    header = root.find(f"{{{NS.SOAP}}}Header")
    if header is None:
        header = root.find(f"{{{NS.SOAP11}}}Header")

    body = root.find(f"{{{NS.SOAP}}}Body")
    if body is None:
        body = root.find(f"{{{NS.SOAP11}}}Body")

    if body is None:
        errors.append("Missing SOAP Body element")

    return len(errors) == 0, errors


def validate_wsa_headers(xml_bytes: bytes, expected_action: str = None) -> tuple:
    """
    Validate WS-Addressing headers.

    Args:
        xml_bytes: SOAP message
        expected_action: Expected Action URI (optional)

    Returns:
        Tuple of (is_valid: bool, errors: list[str])
    """
    errors = []

    tree = etree.parse(BytesIO(xml_bytes))
    root = tree.getroot()

    # Find Action
    action = root.find(f".//{{{NS.WSA}}}Action")
    if action is None:
        errors.append("Missing wsa:Action header")
    elif expected_action and action.text.strip() != expected_action:
        errors.append(f"Action mismatch: '{action.text.strip()}' != '{expected_action}'")

    return len(errors) == 0, errors


class XCEPValidator:
    """Validator for MS-XCEP GetPoliciesResponse messages."""

    def __init__(self, xml_bytes: bytes):
        """Initialize with XML response bytes."""
        self.tree = etree.parse(BytesIO(xml_bytes))
        self.root = self.tree.getroot()
        self.errors = []
        self.warnings = []

    def validate_all(self) -> tuple:
        """
        Run all validations.

        Returns:
            Tuple of (is_valid: bool, errors: list, warnings: list)
        """
        self.errors = []
        self.warnings = []

        self._validate_structure()
        self._validate_oid_references()
        self._validate_ca_references()
        self._validate_policy_attributes()

        return len(self.errors) == 0, self.errors, self.warnings

    def _validate_structure(self) -> None:
        """Validate basic XCEP response structure."""
        # Check for GetPoliciesResponse
        gpr = self.root.find(f".//{{{NS.XCEP}}}GetPoliciesResponse")
        if gpr is None:
            self.errors.append("Missing GetPoliciesResponse element")
            return

        # Check for response element
        response = gpr.find(f"{{{NS.XCEP}}}response")
        if response is None:
            self.errors.append("Missing response element in GetPoliciesResponse")
            return

        # Required elements INSIDE response
        response_required = ["policyID", "policyFriendlyName", "policies"]
        for elem_name in response_required:
            elem = response.find(f"{{{NS.XCEP}}}{elem_name}")
            if elem is None:
                self.errors.append(f"Missing required element in response: {elem_name}")

        # Required elements at GetPoliciesResponse level (NOT inside response)
        # Per MS-XCEP spec, cAs and oIDs are siblings of response
        gpr_required = ["cAs", "oIDs"]
        for elem_name in gpr_required:
            elem = gpr.find(f"{{{NS.XCEP}}}{elem_name}")
            if elem is None:
                self.errors.append(f"Missing required element in GetPoliciesResponse: {elem_name}")

    def _validate_oid_references(self) -> None:
        """Validate that all policy OID references exist in OID collection."""
        # Build OID reference map
        oid_refs = {}
        for oid in self.root.findall(f".//{{{NS.XCEP}}}oID"):
            ref_id = oid.find(f"{{{NS.XCEP}}}oIDReferenceID")
            if ref_id is not None and ref_id.text:
                oid_refs[ref_id.text] = oid.find(f"{{{NS.XCEP}}}value")

        # Check for duplicates
        ref_ids = [
            oid.find(f"{{{NS.XCEP}}}oIDReferenceID").text
            for oid in self.root.findall(f".//{{{NS.XCEP}}}oID")
            if oid.find(f"{{{NS.XCEP}}}oIDReferenceID") is not None
        ]
        if len(ref_ids) != len(set(ref_ids)):
            self.errors.append("Duplicate oIDReferenceID values found")

        # Check policy references
        for policy in self.root.findall(f".//{{{NS.XCEP}}}policy"):
            policy_oid_ref = policy.find(f"{{{NS.XCEP}}}policyOIDReference")
            if policy_oid_ref is not None and policy_oid_ref.text:
                if policy_oid_ref.text not in oid_refs:
                    self.errors.append(
                        f"Policy references non-existent OID: {policy_oid_ref.text}"
                    )

            # Check hash algorithm reference
            attrs = policy.find(f"{{{NS.XCEP}}}attributes")
            if attrs is not None:
                hash_ref = attrs.find(f"{{{NS.XCEP}}}hashAlgorithmOIDReference")
                if hash_ref is not None and hash_ref.text:
                    if hash_ref.get(f"{{{NS.XSI}}}nil") != "true":
                        if hash_ref.text not in oid_refs:
                            self.warnings.append(
                                f"Hash algorithm references non-existent OID: {hash_ref.text}"
                            )

    def _validate_ca_references(self) -> None:
        """Validate CA references in policies."""
        # Build CA reference map
        ca_refs = {}
        for ca in self.root.findall(f".//{{{NS.XCEP}}}cA"):
            ref_id = ca.find(f"{{{NS.XCEP}}}cAReferenceID")
            if ref_id is not None and ref_id.text:
                ca_refs[ref_id.text] = ca

        # Check policy CA references
        for policy in self.root.findall(f".//{{{NS.XCEP}}}policy"):
            cas = policy.find(f"{{{NS.XCEP}}}cAs")
            if cas is not None:
                for ca_ref in cas.findall(f"{{{NS.XCEP}}}cAReference"):
                    if ca_ref.text and ca_ref.text not in ca_refs:
                        self.errors.append(
                            f"Policy references non-existent CA: {ca_ref.text}"
                        )

    def _validate_policy_attributes(self) -> None:
        """Validate policy attributes."""
        for policy in self.root.findall(f".//{{{NS.XCEP}}}policy"):
            attrs = policy.find(f"{{{NS.XCEP}}}attributes")
            if attrs is None:
                self.errors.append("Policy missing attributes element")
                continue

            # Check common name
            cn = attrs.find(f"{{{NS.XCEP}}}commonName")
            if cn is None or not cn.text:
                self.warnings.append("Policy missing commonName")

            # Check certificate validity
            validity = attrs.find(f"{{{NS.XCEP}}}certificateValidity")
            if validity is not None:
                vp = validity.find(f"{{{NS.XCEP}}}validityPeriodSeconds")
                rp = validity.find(f"{{{NS.XCEP}}}renewalPeriodSeconds")

                if vp is not None and vp.text:
                    try:
                        vp_val = int(vp.text)
                        if vp_val <= 0:
                            self.errors.append("validityPeriodSeconds must be positive")
                    except ValueError:
                        self.errors.append("validityPeriodSeconds must be integer")

                if rp is not None and rp.text:
                    try:
                        rp_val = int(rp.text)
                        if rp_val <= 0:
                            self.errors.append("renewalPeriodSeconds must be positive")
                    except ValueError:
                        self.errors.append("renewalPeriodSeconds must be integer")

    def get_oid_map(self) -> dict:
        """Get mapping of OID reference IDs to OID values."""
        oid_map = {}
        for oid in self.root.findall(f".//{{{NS.XCEP}}}oID"):
            ref_id = oid.find(f"{{{NS.XCEP}}}oIDReferenceID")
            value = oid.find(f"{{{NS.XCEP}}}value")
            if ref_id is not None and value is not None:
                oid_map[ref_id.text] = value.text
        return oid_map

    def get_ca_uris(self) -> list:
        """Get all CA URIs from the response."""
        uris = []
        for uri in self.root.findall(f".//{{{NS.XCEP}}}cA/{{{NS.XCEP}}}uris/{{{NS.XCEP}}}uri/{{{NS.XCEP}}}uri"):
            if uri.text:
                uris.append(uri.text)
        return uris


class WSTEPValidator:
    """Validator for MS-WSTEP RequestSecurityTokenResponse messages."""

    def __init__(self, xml_bytes: bytes):
        """Initialize with XML response bytes."""
        self.tree = etree.parse(BytesIO(xml_bytes))
        self.root = self.tree.getroot()
        self.errors = []
        self.warnings = []

    def validate_all(self) -> tuple:
        """
        Run all validations.

        Returns:
            Tuple of (is_valid: bool, errors: list, warnings: list)
        """
        self.errors = []
        self.warnings = []

        self._validate_structure()
        self._validate_token()
        self._validate_pkcs7()

        return len(self.errors) == 0, self.errors, self.warnings

    def _validate_structure(self) -> None:
        """Validate basic WSTEP response structure."""
        # Check for RSTR collection
        rstr_coll = self.root.find(f".//{{{NS.WST}}}RequestSecurityTokenResponseCollection")
        if rstr_coll is None:
            # Some implementations use single RSTR
            rstr = self.root.find(f".//{{{NS.WST}}}RequestSecurityTokenResponse")
            if rstr is None:
                self.errors.append("Missing RequestSecurityTokenResponse(Collection)")
                return
        else:
            rstr = rstr_coll.find(f"{{{NS.WST}}}RequestSecurityTokenResponse")
            if rstr is None:
                self.errors.append("Missing RequestSecurityTokenResponse in collection")
                return

        # Check TokenType
        token_type = rstr.find(f"{{{NS.WST}}}TokenType")
        if token_type is None:
            self.warnings.append("Missing TokenType element")

    def _validate_token(self) -> None:
        """Validate RequestedSecurityToken."""
        rst = self.root.find(f".//{{{NS.WST}}}RequestedSecurityToken")
        if rst is None:
            # Might be pending/denied - check disposition
            disp = self.root.find(f".//{{{NS.ENROLLMENT}}}DispositionMessage")
            if disp is not None:
                return  # OK - this is a non-issued response
            self.errors.append("Missing RequestedSecurityToken (and no DispositionMessage)")
            return

        # Check for BinarySecurityToken
        bst = rst.find(f"{{{NS.WSSE}}}BinarySecurityToken")
        if bst is None:
            self.errors.append("Missing BinarySecurityToken in RequestedSecurityToken")
            return

        # Check ValueType
        value_type = bst.get("ValueType", "")
        if "PKCS7" not in value_type and "X509" not in value_type:
            self.warnings.append(f"Unexpected ValueType: {value_type}")

        # Check content is base64
        if bst.text:
            import base64
            try:
                base64.b64decode(bst.text)
            except Exception:
                self.errors.append("BinarySecurityToken is not valid base64")

    def _validate_pkcs7(self) -> None:
        """Validate PKCS#7 structure if present."""
        bst = self.root.find(f".//{{{NS.WST}}}RequestedSecurityToken/{{{NS.WSSE}}}BinarySecurityToken")
        if bst is None or not bst.text:
            return

        import base64
        try:
            pkcs7_data = base64.b64decode(bst.text)
        except Exception:
            return  # Already reported in _validate_token

        # Try to parse as PKCS#7
        try:
            from cryptography.hazmat.primitives.serialization import pkcs7
            certs = pkcs7.load_der_pkcs7_certificates(pkcs7_data)

            if len(certs) == 0:
                self.errors.append("PKCS#7 contains no certificates")
            elif len(certs) == 1:
                self.warnings.append("PKCS#7 contains only 1 certificate (no chain)")

        except Exception as e:
            self.errors.append(f"Failed to parse PKCS#7: {e}")

    def get_certificate_chain(self) -> list:
        """
        Extract certificate chain from PKCS#7.

        Returns:
            List of cryptography X509 certificate objects
        """
        bst = self.root.find(f".//{{{NS.WST}}}RequestedSecurityToken/{{{NS.WSSE}}}BinarySecurityToken")
        if bst is None or not bst.text:
            return []

        import base64
        try:
            pkcs7_data = base64.b64decode(bst.text)
            from cryptography.hazmat.primitives.serialization import pkcs7
            return pkcs7.load_der_pkcs7_certificates(pkcs7_data)
        except Exception:
            return []


def validate_ca_uri_format(uri: str) -> tuple:
    """
    Validate CA URI format for Windows compatibility.

    Expected format:
    https://<fqdn>[:<port>]/ADPolicyProvider_CES_Kerberos/service.svc/CES

    Returns:
        Tuple of (is_valid: bool, errors: list)
    """
    errors = []

    if not uri:
        return False, ["URI is empty"]

    # Must be HTTPS
    if not uri.startswith("https://"):
        errors.append("URI must use HTTPS")

    # Must not have 0.0.0.0
    if "0.0.0.0" in uri:
        errors.append("URI contains 0.0.0.0 (should be FQDN)")

    # Must not have double slashes (except https://)
    if "//" in uri[8:]:
        errors.append("URI contains double slashes")

    # Should end with expected path
    expected_paths = [
        "/ADPolicyProvider_CES_Kerberos/service.svc/CES",
        "/ADPolicyProvider_ces_kerberos/service.svc/ces",
    ]
    if not any(uri.endswith(path) for path in expected_paths):
        errors.append(f"URI should end with CES service path")

    return len(errors) == 0, errors


# Add NS.SOAP11 and NS.ENROLLMENT if not defined
if not hasattr(NS, 'SOAP11'):
    NS.SOAP11 = "http://schemas.xmlsoap.org/soap/envelope/"
if not hasattr(NS, 'ENROLLMENT'):
    NS.ENROLLMENT = "http://schemas.microsoft.com/windows/pki/2009/01/enrollment"
if not hasattr(NS, 'XSI'):
    NS.XSI = "http://www.w3.org/2001/XMLSchema-instance"
