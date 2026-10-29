import base64
import xml.etree.ElementTree as ET

import pytest

from certipy.lib.ces import (
    ADDR_NS,
    AUTHZ_NS,
    ENCODING_TYPE_BASE64,
    REQUEST_TYPE_ISSUE,
    SOAP_NS,
    TOKEN_TYPE_X509V3,
    VALUE_TYPE_PKCS10,
    WSS_NS,
    WST_NS,
    WSTEP_ACTION,
    build_wstep_request,
    default_ces_path,
)

CES_URL = "https://braavos.essos.local/ESSOS-CA_CES_Kerberos/service.svc/CES"
CSR = b"\x30\x03\x02\x01\x00"


def _context_items(root: ET.Element) -> list[tuple[str | None, str | None]]:
    items = root.findall(f".//{{{AUTHZ_NS}}}ContextItem")
    return [(i.get("Name"), i.findtext(f"{{{AUTHZ_NS}}}Value")) for i in items]


def test_default_ces_path():
    assert default_ces_path("ESSOS-CA") == "/ESSOS-CA_CES_Kerberos/service.svc/CES"


def test_default_ces_path_quotes_ca_name():
    assert default_ces_path("My CA") == "/My%20CA_CES_Kerberos/service.svc/CES"


def test_build_wstep_request_headers():
    root = ET.fromstring(
        build_wstep_request(
            CES_URL, CSR, ["CertificateTemplate:User"], message_id="urn:uuid:1"
        )
    )
    header = root.find(f"{{{SOAP_NS}}}Header")
    assert header is not None
    assert header.findtext(f"{{{ADDR_NS}}}Action") == WSTEP_ACTION
    assert header.findtext(f"{{{ADDR_NS}}}MessageID") == "urn:uuid:1"
    assert header.findtext(f"{{{ADDR_NS}}}To") == CES_URL


def test_build_wstep_request_body():
    root = ET.fromstring(
        build_wstep_request(CES_URL, CSR, ["CertificateTemplate:User"])
    )
    rst = root.find(f"{{{SOAP_NS}}}Body/{{{WST_NS}}}RequestSecurityToken")
    assert rst is not None
    assert rst.findtext(f"{{{WST_NS}}}TokenType") == TOKEN_TYPE_X509V3
    assert rst.findtext(f"{{{WST_NS}}}RequestType") == REQUEST_TYPE_ISSUE
    token = rst.find(f"{{{WSS_NS}}}BinarySecurityToken")
    assert token is not None
    assert token.get("ValueType") == VALUE_TYPE_PKCS10
    assert token.get("EncodingType") == ENCODING_TYPE_BASE64
    assert base64.b64decode(token.text or "") == CSR


def test_build_wstep_request_generates_message_id():
    root = ET.fromstring(
        build_wstep_request(CES_URL, CSR, ["CertificateTemplate:User"])
    )
    message_id = root.findtext(f".//{{{ADDR_NS}}}MessageID") or ""
    assert message_id.startswith("urn:uuid:")


def test_build_wstep_request_context_items():
    root = ET.fromstring(
        build_wstep_request(
            CES_URL,
            CSR,
            [
                "CertificateTemplate:User",
                "SAN:upn=administrator@essos.local&dns=braavos.essos.local",
            ],
        )
    )
    assert _context_items(root) == [
        ("CertificateTemplate", "User"),
        ("SAN", "upn=administrator@essos.local&dns=braavos.essos.local"),
    ]


def test_build_wstep_request_escapes_values():
    root = ET.fromstring(
        build_wstep_request(CES_URL + "?a=1&b=2", CSR, ['Certificate"Template:<A&B>'])
    )
    assert root.findtext(f".//{{{ADDR_NS}}}To") == CES_URL + "?a=1&b=2"
    assert _context_items(root) == [('Certificate"Template', "<A&B>")]


def test_build_wstep_request_rejects_malformed_attribute():
    with pytest.raises(ValueError):
        build_wstep_request(CES_URL, CSR, ["NoColonHere"])
