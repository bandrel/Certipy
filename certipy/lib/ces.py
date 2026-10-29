"""
Certificate Enrollment Web Service (CES) support for Certipy.

This module implements the MS-WSTEP (WS-Trust X.509v3 Token Enrollment)
messages used by the AD CS Certificate Enrollment Web Service, typically
exposed at https://<host>/<CA name>_CES_Kerberos/service.svc/CES.

Key components:
- default_ces_path: Build the default CES endpoint path for a CA
- build_wstep_request: Build a WS-Trust RequestSecurityToken SOAP envelope

The message format follows the CES relay attack in Impacket
(https://github.com/fortra/impacket/pull/2325).
"""

import base64
import uuid
from html import escape
from typing import List, Optional
from urllib.parse import quote

# =========================================================================
# Constants
# =========================================================================

SOAP_NS = "http://www.w3.org/2003/05/soap-envelope"
ADDR_NS = "http://www.w3.org/2005/08/addressing"
WST_NS = "http://docs.oasis-open.org/ws-sx/ws-trust/200512"
WSS_NS = (
    "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
)
WSU_NS = (
    "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
)
AUTHZ_NS = "http://schemas.xmlsoap.org/ws/2006/12/authorization"
ENROLL_NS = "http://schemas.microsoft.com/windows/pki/2009/01/enrollment"

WSTEP_ACTION = f"{ENROLL_NS}/RST/wstep"
TOKEN_TYPE_X509V3 = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3"
REQUEST_TYPE_ISSUE = f"{WST_NS}/Issue"
VALUE_TYPE_PKCS10 = f"{ENROLL_NS}#PKCS10"
ENCODING_TYPE_BASE64 = f"{WSS_NS}#base64binary"

SOAP_CONTENT_TYPE = "application/soap+xml; charset=utf-8"

# Upper bound on CES response bodies we are willing to parse
MAX_RESPONSE_SIZE = 10 * 1024 * 1024

# =========================================================================
# Request building
# =========================================================================


def default_ces_path(ca: str) -> str:
    """
    Get the default CES endpoint path for a CA using Windows integrated authentication.

    Args:
        ca: Certificate Authority name

    Returns:
        URL path of the CES endpoint
    """
    return f"/{quote(ca)}_CES_Kerberos/service.svc/CES"


def _build_additional_context(attributes_list: List[str]) -> str:
    """
    Convert certificate request attributes to a WSTEP AdditionalContext element.

    Args:
        attributes_list: Attributes in "Name:Value" form

    Returns:
        AdditionalContext XML element

    Raises:
        ValueError: If an attribute is not in "Name:Value" form
    """
    items = []
    for attribute in attributes_list:
        name, separator, value = attribute.partition(":")
        if not separator:
            raise ValueError(f"Invalid certificate request attribute: {attribute!r}")
        items.append(
            f'<ContextItem Name="{escape(name)}">'
            f"<Value>{escape(value)}</Value>"
            "</ContextItem>"
        )

    return f'<AdditionalContext xmlns="{AUTHZ_NS}">{"".join(items)}</AdditionalContext>'


def build_wstep_request(
    to_url: str,
    csr: bytes,
    attributes_list: List[str],
    message_id: Optional[str] = None,
) -> bytes:
    """
    Build a WSTEP RequestSecurityToken message for a new certificate.

    Args:
        to_url: Full CES endpoint URL for the WS-Addressing To header
        csr: Certificate signing request in DER format
        attributes_list: Certificate request attributes in "Name:Value" form
        message_id: Optional WS-Addressing message ID (random UUID by default)

    Returns:
        UTF-8 encoded SOAP envelope
    """
    if message_id is None:
        message_id = f"urn:uuid:{uuid.uuid4()}"

    csr_b64 = base64.b64encode(csr).decode()
    context = _build_additional_context(attributes_list)

    envelope = (
        '<?xml version="1.0" encoding="utf-8"?>'
        f'<s:Envelope xmlns:s="{SOAP_NS}" xmlns:a="{ADDR_NS}">'
        "<s:Header>"
        f'<a:Action s:mustUnderstand="1">{WSTEP_ACTION}</a:Action>'
        f"<a:MessageID>{escape(message_id)}</a:MessageID>"
        f'<a:To s:mustUnderstand="1">{escape(to_url)}</a:To>'
        "</s:Header>"
        "<s:Body>"
        f'<RequestSecurityToken PreferredLanguage="en-US" xmlns="{WST_NS}">'
        f"<TokenType>{TOKEN_TYPE_X509V3}</TokenType>"
        f"<RequestType>{REQUEST_TYPE_ISSUE}</RequestType>"
        f'<BinarySecurityToken ValueType="{VALUE_TYPE_PKCS10}" '
        f'EncodingType="{ENCODING_TYPE_BASE64}" u:Id="" '
        f'xmlns:u="{WSU_NS}" xmlns="{WSS_NS}">{csr_b64}</BinarySecurityToken>'
        f"{context}"
        "</RequestSecurityToken>"
        "</s:Body>"
        "</s:Envelope>"
    )

    return envelope.encode("utf-8")
