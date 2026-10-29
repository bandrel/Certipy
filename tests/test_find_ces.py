from types import SimpleNamespace
from typing import Any, Callable

import httpx

from certipy.commands.find import Find
from certipy.lib.ldap import LDAPEntry

CES_URI = "https://braavos.essos.local/ESSOS-CA_CES_Kerberos/service.svc/CES"


def _find() -> Find:
    f = Find.__new__(Find)  # bypass __init__; we only test pure helpers
    target: Any = SimpleNamespace(
        timeout=5, resolver=SimpleNamespace(resolve=lambda n: "10.0.0.5")
    )
    f.target = target
    return f


def _factory(
    handler: Callable[[httpx.Request], httpx.Response],
) -> Callable[[], httpx.Client]:
    return lambda: httpx.Client(transport=httpx.MockTransport(handler))


def test_probe_enrollment_server_reachable():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path.endswith("/service.svc/CES")
        assert request.headers["Host"] == "braavos.essos.local"
        return httpx.Response(401, headers={"WWW-Authenticate": "Negotiate"})

    f = _find()
    f.check_enrollment_channel_binding = lambda parsed, ip: True  # type: ignore
    reachable, cb = f.probe_enrollment_server(
        CES_URI, session_factory=_factory(handler)
    )
    assert reachable is True
    assert cb is True


def test_probe_enrollment_server_http_skips_channel_binding():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401)

    reachable, cb = _find().probe_enrollment_server(
        "http://x/y_CES_Kerberos/service.svc/CES", session_factory=_factory(handler)
    )
    assert reachable is True
    assert cb is None


def test_probe_enrollment_server_unreachable():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    reachable, cb = _find().probe_enrollment_server(
        CES_URI, session_factory=_factory(handler)
    )
    assert reachable is False
    assert cb is None


def test_probe_enrollment_server_channel_binding_error_is_none():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401)

    f = _find()

    def boom(parsed: httpx.URL, ip: str):
        raise RuntimeError("x")

    f.check_enrollment_channel_binding = boom  # type: ignore
    reachable, cb = f.probe_enrollment_server(
        CES_URI, session_factory=_factory(handler)
    )
    assert reachable is True
    assert cb is None


def _ep(**kw: Any) -> dict[str, Any]:
    base = {
        "uri": "https://h/ca_CES_Kerberos/service.svc/CES",
        "auth": ["Kerberos"],
        "scheme": "https",
        "reachable": True,
        "channel_binding": None,
        "priority": 1,
        "renewals_only": False,
    }
    base.update(kw)
    return base


def test_esc8_ces_relayable_http():
    ep = [_ep(uri="http://h/ca_CES_Kerberos/service.svc/CES", scheme="http")]
    assert "CES" in (Find.evaluate_esc8_ces(ep, True) or "")


def test_esc8_ces_https_epa_not_relayable():
    assert Find.evaluate_esc8_ces([_ep(channel_binding=True)], True) is None


def test_esc8_ces_usernamepassword_not_relayable():
    ep = [_ep(auth=["UsernameAndPassword"], channel_binding=False)]
    assert Find.evaluate_esc8_ces(ep, True) is None


def test_esc8_ces_https_epa_disabled_relayable():
    assert Find.evaluate_esc8_ces([_ep(channel_binding=False)], True)


def test_esc8_ces_https_epa_unknown_is_not_hard_finding():
    ep = [_ep(channel_binding="Unknown")]
    assert Find.evaluate_esc8_ces(ep, True) is None
    assert Find.evaluate_esc8_ces_remark(ep, True)


def test_esc8_ces_unreachable_or_not_issuing():
    assert Find.evaluate_esc8_ces([_ep(scheme="http", reachable=False)], True) is None
    assert Find.evaluate_esc8_ces([_ep(scheme="http")], False) is None


def test_check_enrollment_web_service_populates_list():
    f = _find()
    f.probe_enrollment_server = lambda uri: (True, False)  # type: ignore
    ca = LDAPEntry(
        attributes={
            "msPKI-Enrollment-Servers": [
                b"1\n2\n0\nhttps://ca/ESSOS-CA_CES_Kerberos/service.svc/CES\n0"
            ]
        }
    )
    result = f._check_enrollment_web_service(ca)
    assert len(result) == 1
    ep = result[0]
    assert set(ep) == {
        "uri",
        "auth",
        "priority",
        "renewals_only",
        "scheme",
        "reachable",
        "channel_binding",
    }
    assert ep["uri"] == "https://ca/ESSOS-CA_CES_Kerberos/service.svc/CES"
    assert ep["scheme"] == "https"
    assert ep["reachable"] is True
    assert ep["channel_binding"] is False
    assert "Kerberos" in ep["auth"]


def test_check_enrollment_web_service_absent():
    assert _find()._check_enrollment_web_service(LDAPEntry(attributes={})) == []


def test_probe_enrollment_server_malformed_uri():
    assert _find().probe_enrollment_server("http://h:abc/") == (False, None)


def test_format_enrollment_web_service():
    out = Find.format_enrollment_web_service(
        [_ep(channel_binding=False, auth=["Kerberos"])]
    )
    assert out == [
        "https://h/ca_CES_Kerberos/service.svc/CES [Kerberos] reachable=True EPA=Disabled"
    ]
