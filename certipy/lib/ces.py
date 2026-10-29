"""
Certificate Enrollment Web Service (CES) support for Certipy.

This module implements the MS-WSTEP (WS-Trust X.509v3 Token Enrollment)
messages used by the AD CS Certificate Enrollment Web Service, typically
exposed at https://<host>/<CA name>_CES_Kerberos/service.svc/CES.

Key components:
- default_ces_path: Build the default CES endpoint path for a CA
- build_wstep_request: Build a WS-Trust RequestSecurityToken SOAP envelope
- parse_wstep_response: Parse a RequestSecurityTokenResponse or SOAP fault
- CESError: Raised for SOAP faults and unusable responses

The message format follows the CES relay attack in Impacket
(https://github.com/fortra/impacket/pull/2325).
"""

import base64
import re
import uuid
from dataclasses import dataclass
from html import escape
from typing import List, Optional
from urllib.parse import quote
from xml.etree import ElementTree

from certipy.lib.certificate import der_to_cert, x509

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


# =========================================================================
# Response parsing
# =========================================================================


class CESError(Exception):
    """
    Error returned by the Certificate Enrollment Web Service.
    """

    def __init__(
        self,
        message: str,
        error_code: Optional[int] = None,
        request_id: Optional[int] = None,
    ):
        """
        Initialize the CES error.

        Args:
            message: Fault reason or error description
            error_code: HRESULT from the fault detail, as an unsigned 32-bit value
            request_id: Request ID from the fault detail
        """
        super().__init__(message)
        self.error_code = error_code
        self.request_id = request_id


@dataclass
class WstepResponse:
    """
    Parsed WSTEP RequestSecurityTokenResponse.

    A response without a certificate means the request is pending.
    """

    certificate: Optional[x509.Certificate]
    request_id: Optional[int]
    disposition_message: Optional[str]


def _find_text(element: ElementTree.Element, path: str) -> Optional[str]:
    """
    Get the stripped text of the first element matching a path.

    Args:
        element: Element to search from
        path: ElementTree path expression

    Returns:
        Element text, or None if missing or empty
    """
    text = element.findtext(path)
    if text is None:
        return None
    return text.strip() or None


def _parse_int(value: Optional[str]) -> Optional[int]:
    """
    Parse an optional decimal integer.

    Args:
        value: Decimal string or None

    Returns:
        Parsed integer, or None if missing or invalid
    """
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def parse_wstep_response(data: bytes) -> WstepResponse:
    """
    Parse a WSTEP response from the Certificate Enrollment Web Service.

    Args:
        data: Raw response body

    Returns:
        Parsed response; certificate is None if the request is pending

    Raises:
        CESError: If the service returned a SOAP fault or an unusable response
    """
    if not data:
        raise CESError("CES returned an empty response")
    if len(data) > MAX_RESPONSE_SIZE:
        raise CESError(f"CES response exceeds {MAX_RESPONSE_SIZE} bytes")

    try:
        root = ElementTree.fromstring(data)
    except ElementTree.ParseError as e:
        raise CESError(f"CES returned malformed XML: {e}") from e

    request_id = _parse_int(_find_text(root, f".//{{{ENROLL_NS}}}RequestID"))

    fault = root.find(f".//{{{SOAP_NS}}}Fault")
    if fault is not None:
        reason = _find_text(fault, f".//{{{SOAP_NS}}}Text") or "Unspecified fault"
        error_code = _parse_int(_find_text(fault, f".//{{{ENROLL_NS}}}ErrorCode"))
        if error_code is not None:
            # ErrorCode is a signed HRESULT
            error_code &= 0xFFFFFFFF
        raise CESError(reason, error_code=error_code, request_id=request_id)

    certificate = None
    for token in root.iter(f"{{{WSS_NS}}}BinarySecurityToken"):
        if "X509v3" not in token.get("ValueType", ""):
            continue

        value = re.sub(r"\s+", "", token.text or "")
        if not value:
            continue

        try:
            certificate = der_to_cert(base64.b64decode(value, validate=True))
        except ValueError as e:
            raise CESError("CES returned an invalid X509v3 certificate token") from e

    return WstepResponse(
        certificate=certificate,
        request_id=request_id,
        disposition_message=_find_text(root, f".//{{{ENROLL_NS}}}DispositionMessage"),
    )
