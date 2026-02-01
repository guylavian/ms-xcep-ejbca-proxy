#!/usr/bin/env python3
"""
Windows Certificate Enrollment Client Simulator.

Simulates the behavior of a Windows client performing certificate autoenrollment
via MS-XCEP (GetPolicies) and MS-WSTEP (RequestSecurityToken) protocols.

This tool can be used to test the proxy server without an actual Windows machine.
"""

import argparse
import base64
import sys
import urllib3
from datetime import datetime
from lxml import etree

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

# Disable SSL warnings for self-signed certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class WindowsClientSimulator:
    """Simulates Windows certificate enrollment client."""

    SOAP_CONTENT_TYPE = "application/soap+xml; charset=utf-8"

    def __init__(self, base_url: str, verify_ssl: bool = False):
        """
        Initialize simulator.

        Args:
            base_url: Base URL of the proxy server (e.g., https://localhost:8443)
            verify_ssl: Whether to verify SSL certificates
        """
        self.base_url = base_url.rstrip("/")
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.session.verify = verify_ssl

        # Endpoints
        self.cep_url = f"{self.base_url}/ADPolicyProvider_CEP_Kerberos/service.svc/CEP"
        self.ces_url = f"{self.base_url}/ADPolicyProvider_CES_Kerberos/service.svc/CES"

    def _send_soap_request(self, url: str, soap_body: str, action: str) -> bytes:
        """Send SOAP request and return response."""
        headers = {
            "Content-Type": self.SOAP_CONTENT_TYPE,
            "SOAPAction": f'"{action}"',
            # Mock Kerberos token for testing
            "Authorization": "Negotiate YIIBhwYJKoZIhvcSAQICAQBuggF2MIIBcqADAgEFoQMCAQ6iBwMFACAAAACj",
        }

        response = self.session.post(url, data=soap_body.encode("utf-8"), headers=headers)
        return response.content

    def get_policies(self) -> dict:
        """
        Send GetPolicies request (MS-XCEP).

        Returns:
            Dict with policies, CAs, and OIDs
        """
        print("\n" + "=" * 60)
        print("STEP 1: GetPolicies (MS-XCEP)")
        print("=" * 60)
        print(f"URL: {self.cep_url}")

        soap_request = """<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:a="http://www.w3.org/2005/08/addressing"
            xmlns:u="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
    <s:Header>
        <a:Action s:mustUnderstand="1">
            http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy/IPolicy/GetPolicies
        </a:Action>
        <a:MessageID>urn:uuid:simulator-{timestamp}</a:MessageID>
        <a:ReplyTo>
            <a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
        </a:ReplyTo>
        <a:To s:mustUnderstand="1">{url}</a:To>
    </s:Header>
    <s:Body xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
        <GetPolicies xmlns="http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy">
            <client>
                <lastUpdate xsi:nil="true"/>
                <preferredLanguage xsi:nil="true"/>
            </client>
            <requestFilter xsi:nil="true"/>
        </GetPolicies>
    </s:Body>
</s:Envelope>""".format(
            timestamp=datetime.now().isoformat(),
            url=self.cep_url
        )

        print("\nSending request...")
        response = self._send_soap_request(
            self.cep_url,
            soap_request,
            "http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy/IPolicy/GetPolicies"
        )

        # Parse response
        result = self._parse_get_policies_response(response)

        print(f"\nResponse received: {len(response)} bytes")
        print(f"  Policy ID: {result.get('policy_id', 'N/A')}")
        print(f"  Policies found: {len(result.get('policies', []))}")
        print(f"  CAs found: {len(result.get('cas', []))}")
        print(f"  OIDs found: {len(result.get('oids', []))}")

        if result.get("policies"):
            print("\n  Available templates:")
            for p in result["policies"]:
                print(f"    - {p['name']} (OID ref: {p['oid_ref']}, AutoEnroll: {p['auto_enroll']})")

        if result.get("cas"):
            print("\n  Certificate Authorities:")
            for ca in result["cas"]:
                print(f"    - {ca['uri']}")

        return result

    def _parse_get_policies_response(self, response_xml: bytes) -> dict:
        """Parse GetPoliciesResponse XML."""
        NS = {
            "s": "http://www.w3.org/2003/05/soap-envelope",
            "xcep": "http://schemas.microsoft.com/windows/pki/2009/01/enrollmentpolicy",
        }

        try:
            root = etree.fromstring(response_xml)
        except etree.XMLSyntaxError as e:
            print(f"  ERROR: Failed to parse response: {e}")
            print(f"  Response: {response_xml[:500]}")
            return {"error": str(e)}

        # Check for SOAP fault
        fault = root.find(".//s:Fault", NS)
        if fault is not None:
            reason = fault.find(".//s:Reason/s:Text", NS)
            error_msg = reason.text if reason is not None else "Unknown error"
            print(f"  ERROR: SOAP Fault: {error_msg}")
            return {"error": error_msg}

        result = {
            "policies": [],
            "cas": [],
            "oids": [],
        }

        # Get policy ID
        policy_id = root.find(".//xcep:policyID", NS)
        if policy_id is not None:
            result["policy_id"] = policy_id.text

        # Parse policies
        for policy in root.findall(".//xcep:policy", NS):
            oid_ref = policy.find("xcep:policyOIDReference", NS)
            attrs = policy.find("xcep:attributes", NS)

            policy_data = {
                "oid_ref": oid_ref.text if oid_ref is not None else None,
                "name": None,
                "auto_enroll": False,
            }

            if attrs is not None:
                cn = attrs.find("xcep:commonName", NS)
                if cn is not None:
                    policy_data["name"] = cn.text

                perm = attrs.find("xcep:permission", NS)
                if perm is not None:
                    auto = perm.find("xcep:autoEnroll", NS)
                    if auto is not None:
                        policy_data["auto_enroll"] = auto.text == "true"

            result["policies"].append(policy_data)

        # Parse CAs
        for ca in root.findall(".//xcep:cA", NS):
            uri_elem = ca.find(".//xcep:uri/xcep:uri", NS)
            ca_data = {
                "uri": uri_elem.text if uri_elem is not None else None,
                "ref_id": None,
            }
            ref_id = ca.find("xcep:cAReferenceID", NS)
            if ref_id is not None:
                ca_data["ref_id"] = ref_id.text
            result["cas"].append(ca_data)

        # Parse OIDs
        for oid in root.findall(".//xcep:oID", NS):
            value = oid.find("xcep:value", NS)
            name = oid.find("xcep:defaultName", NS)
            ref_id = oid.find("xcep:oIDReferenceID", NS)
            result["oids"].append({
                "value": value.text if value is not None else None,
                "name": name.text if name is not None else None,
                "ref_id": ref_id.text if ref_id is not None else None,
            })

        return result

    def request_certificate(self, template_name: str = "User",
                            common_name: str = "Test User") -> dict:
        """
        Send RequestSecurityToken request (MS-WSTEP).

        Args:
            template_name: Certificate template name
            common_name: Subject CN for the certificate

        Returns:
            Dict with enrollment result
        """
        print("\n" + "=" * 60)
        print("STEP 2: RequestSecurityToken (MS-WSTEP)")
        print("=" * 60)
        print(f"URL: {self.ces_url}")
        print(f"Template: {template_name}")
        print(f"Subject CN: {common_name}")

        # Generate RSA key pair
        print("\nGenerating RSA 2048-bit key pair...")
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )

        # Create CSR
        print("Creating PKCS#10 CSR...")
        csr = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, common_name),
            ])
        ).sign(private_key, hashes.SHA256())

        csr_der = csr.public_bytes(serialization.Encoding.DER)
        csr_b64 = base64.b64encode(csr_der).decode("ascii")

        print(f"CSR size: {len(csr_der)} bytes")

        soap_request = """<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:a="http://www.w3.org/2005/08/addressing"
            xmlns:wst="http://docs.oasis-open.org/ws-sx/ws-trust/200512"
            xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
            xmlns:ac="http://schemas.xmlsoap.org/ws/2006/12/authorization">
    <s:Header>
        <a:Action s:mustUnderstand="1">
            http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RST/wstep
        </a:Action>
        <a:MessageID>urn:uuid:simulator-rst-{timestamp}</a:MessageID>
        <a:ReplyTo>
            <a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
        </a:ReplyTo>
        <a:To s:mustUnderstand="1">{url}</a:To>
    </s:Header>
    <s:Body>
        <wst:RequestSecurityToken>
            <wst:TokenType>
                http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3
            </wst:TokenType>
            <wst:RequestType>
                http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue
            </wst:RequestType>
            <wsse:BinarySecurityToken
                ValueType="http://schemas.microsoft.com/windows/pki/2009/01/enrollment#PKCS10"
                EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#base64binary">
                {csr}
            </wsse:BinarySecurityToken>
            <ac:AdditionalContext>
                <ac:ContextItem Name="CertificateTemplate">
                    <ac:Value>{template}</ac:Value>
                </ac:ContextItem>
                <ac:ContextItem Name="DeviceType">
                    <ac:Value>CIMClient_Windows</ac:Value>
                </ac:ContextItem>
            </ac:AdditionalContext>
        </wst:RequestSecurityToken>
    </s:Body>
</s:Envelope>""".format(
            timestamp=datetime.now().isoformat(),
            url=self.ces_url,
            csr=csr_b64,
            template=template_name
        )

        print("\nSending enrollment request...")
        response = self._send_soap_request(
            self.ces_url,
            soap_request,
            "http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RST/wstep"
        )

        # Parse response
        result = self._parse_rstr_response(response)

        print(f"\nResponse received: {len(response)} bytes")
        print(f"  Status: {result.get('status', 'Unknown')}")

        if result.get("disposition_message"):
            print(f"  Disposition: {result['disposition_message']}")

        if result.get("request_id"):
            print(f"  Request ID: {result['request_id']}")

        if result.get("certificate"):
            cert = result["certificate"]
            print(f"\n  Certificate issued!")
            print(f"    Subject: {cert.subject.rfc4514_string()}")
            print(f"    Issuer: {cert.issuer.rfc4514_string()}")
            print(f"    Serial: {cert.serial_number}")
            print(f"    Not Before: {cert.not_valid_before_utc}")
            print(f"    Not After: {cert.not_valid_after_utc}")

        return result

    def _parse_rstr_response(self, response_xml: bytes) -> dict:
        """Parse RequestSecurityTokenResponse XML."""
        NS = {
            "s": "http://www.w3.org/2003/05/soap-envelope",
            "wst": "http://docs.oasis-open.org/ws-sx/ws-trust/200512",
            "wsse": "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd",
            "enrollment": "http://schemas.microsoft.com/windows/pki/2009/01/enrollment",
        }

        try:
            root = etree.fromstring(response_xml)
        except etree.XMLSyntaxError as e:
            print(f"  ERROR: Failed to parse response: {e}")
            print(f"  Response: {response_xml[:500]}")
            return {"status": "error", "error": str(e)}

        # Check for SOAP fault
        fault = root.find(".//s:Fault", NS)
        if fault is not None:
            reason = fault.find(".//s:Reason/s:Text", NS)
            error_msg = reason.text if reason is not None else "Unknown error"
            print(f"  ERROR: SOAP Fault: {error_msg}")
            return {"status": "error", "error": error_msg}

        result = {"status": "unknown"}

        # Get disposition message
        disp = root.find(".//enrollment:DispositionMessage", NS)
        if disp is not None:
            result["disposition_message"] = disp.text
            if disp.text and "Issued" in disp.text:
                result["status"] = "issued"
            elif disp.text and "pending" in disp.text.lower():
                result["status"] = "pending"
            elif disp.text and "denied" in disp.text.lower():
                result["status"] = "denied"

        # Get request ID
        req_id = root.find(".//enrollment:RequestID", NS)
        if req_id is not None:
            result["request_id"] = req_id.text

        # Get certificate from PKCS#7
        bst = root.find(".//wst:RequestedSecurityToken/wsse:BinarySecurityToken", NS)
        if bst is not None and bst.text:
            try:
                from cryptography.hazmat.primitives.serialization import pkcs7
                pkcs7_data = base64.b64decode(bst.text)
                certs = pkcs7.load_der_pkcs7_certificates(pkcs7_data)
                if certs:
                    result["certificate"] = certs[0]
                    result["certificate_chain"] = certs
                    result["status"] = "issued"
            except Exception as e:
                print(f"  Warning: Could not parse PKCS#7: {e}")

        return result

    def run_full_enrollment(self, template_name: str = "User",
                            common_name: str = "Test User"):
        """Run full enrollment flow: GetPolicies + RequestSecurityToken."""
        print("\n" + "#" * 60)
        print("# Windows Certificate Enrollment Simulator")
        print("#" * 60)
        print(f"Server: {self.base_url}")
        print(f"Time: {datetime.now().isoformat()}")

        # Step 1: Get policies
        policies = self.get_policies()
        if policies.get("error"):
            print(f"\nFailed to get policies: {policies['error']}")
            return False

        # Step 2: Request certificate
        result = self.request_certificate(template_name, common_name)

        print("\n" + "=" * 60)
        print("ENROLLMENT COMPLETE")
        print("=" * 60)

        if result.get("status") == "issued":
            print("Result: SUCCESS - Certificate issued")
            return True
        elif result.get("status") == "pending":
            print("Result: PENDING - Awaiting approval")
            return True
        else:
            print(f"Result: FAILED - {result.get('error', result.get('disposition_message', 'Unknown'))}")
            return False


def main():
    parser = argparse.ArgumentParser(
        description="Windows Certificate Enrollment Client Simulator"
    )
    parser.add_argument(
        "-u", "--url",
        default="https://localhost:8443",
        help="Proxy server URL (default: https://localhost:8443)"
    )
    parser.add_argument(
        "-t", "--template",
        default="User",
        help="Certificate template name (default: User)"
    )
    parser.add_argument(
        "-n", "--name",
        default="Test User",
        help="Subject Common Name (default: Test User)"
    )
    parser.add_argument(
        "--policies-only",
        action="store_true",
        help="Only fetch policies, don't request certificate"
    )
    parser.add_argument(
        "-k", "--insecure",
        action="store_true",
        default=True,
        help="Disable SSL verification (default: True)"
    )

    args = parser.parse_args()

    client = WindowsClientSimulator(args.url, verify_ssl=not args.insecure)

    if args.policies_only:
        client.get_policies()
    else:
        success = client.run_full_enrollment(args.template, args.name)
        sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
