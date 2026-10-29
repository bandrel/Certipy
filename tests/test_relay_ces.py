import argparse
import base64
from types import SimpleNamespace
from typing import Any, Callable, List, Optional

import httpx
import pytest

from certipy.commands import relay as relay_module
from certipy.commands.parsers import relay as relay_parser
from certipy.commands.relay import Relay
from tests.test_ces import _fault, _rstr, _self_signed_der


def test_build_ces_target_keeps_path():
    base_url, to_url, path = Relay._build_ces_target(
        "https://braavos.essos.local/ESSOS-CA_CES_Kerberos/service.svc/CES"
    )
    assert base_url == "https://braavos.essos.local"
    assert to_url == "https://braavos.essos.local/ESSOS-CA_CES_Kerberos/service.svc/CES"
    assert path == "/ESSOS-CA_CES_Kerberos/service.svc/CES"


def test_build_ces_target_adds_scheme():
    base_url, _, path = Relay._build_ces_target(
        "braavos/ESSOS-CA_CES_Kerberos/service.svc/CES"
    )
    assert base_url == "https://braavos"
    assert path == "/ESSOS-CA_CES_Kerberos/service.svc/CES"


def test_build_ces_target_keeps_explicit_port():
    base_url, _, _ = Relay._build_ces_target("https://h:8443/CA_CES/service.svc/CES")
    assert base_url == "https://h:8443"


def _parse(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser()
    relay_parser.add_subparser(p.add_subparsers(dest="action"))
    return p.parse_args(argv)


def test_ces_flag_parsed():
    opts = _parse(
        ["relay", "-target", "https://h/ca_CES_Kerberos/service.svc/CES", "-ces"]
    )
    assert opts.ces is True


def test_ces_flag_defaults_false():
    assert _parse(["relay", "-target", "x"]).ces is False


CES_URL = "https://braavos.essos.local/ESSOS-CA_CES_Kerberos/service.svc/CES"


def _make_attack(
    handler: Callable[[httpx.Request], httpx.Response],
    to_url: str = CES_URL,
    template: Optional[str] = "User",
    username: str = "missandei",
    session_timeout: Optional[float] = 5.0,
) -> relay_module.ADCSHTTPAttackClient:
    client = httpx.Client(
        base_url="https://10.0.0.5",
        transport=httpx.MockTransport(handler),
        timeout=session_timeout,
    )
    client.user = "ESSOS\\missandei"  # type: ignore[attr-defined]
    adcs_relay = SimpleNamespace(
        ces=True,
        ces_to_url=to_url,
        template=template,
        alt_dns=None,
        alt_upn=None,
        alt_sid=None,
        subject=None,
        key_size=2048,
        application_policies=[],
        smime=None,
        archive_key=None,
        out=None,
        pfx_password=None,
        attacked_targets=[],
        forever=True,
        no_skip=True,
        enum_templates=False,
        request_id=None,
    )
    attack = relay_module.ADCSHTTPAttackClient.__new__(
        relay_module.ADCSHTTPAttackClient
    )
    attack.adcs_relay = adcs_relay  # type: ignore[assignment]
    attack.client = client  # type: ignore[attr-defined]
    attack.username = username  # type: ignore[attr-defined]
    attack.config = SimpleNamespace(template=template)  # type: ignore[assignment]
    return attack


def _record_saves(monkeypatch: pytest.MonkeyPatch) -> List[Any]:
    saved: List[Any] = []
    monkeypatch.setattr(
        relay_module, "handle_request_response", lambda *a, **k: saved.append(a)
    )
    return saved


def test_ces_attack_posts_wstep_and_saves(monkeypatch: pytest.MonkeyPatch):
    saved = _record_saves(monkeypatch)
    cert_b64 = base64.b64encode(_self_signed_der()).decode()
    seen: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["method"] = request.method
        seen["path"] = request.url.raw_path.decode()
        seen["body"] = request.content
        seen["ctype"] = request.headers["Content-Type"]
        return httpx.Response(
            200,
            content=_rstr(cert_token=cert_b64),
            headers={"Content-Type": "application/soap+xml"},
        )

    _make_attack(handler)._request_certificate_ces()

    assert seen["method"] == "POST"
    assert seen["path"] == "/ESSOS-CA_CES_Kerberos/service.svc/CES"
    assert seen["ctype"].startswith("application/soap+xml")
    assert b"RequestSecurityToken" in seen["body"]
    assert (
        b'<ContextItem Name="CertificateTemplate"><Value>User</Value></ContextItem>'
        in seen["body"]
    )
    assert len(saved) == 1


def test_ces_attack_fault_does_not_save(monkeypatch: pytest.MonkeyPatch):
    saved = _record_saves(monkeypatch)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, content=_fault("denied", "2148204810", "9"))

    attack = _make_attack(handler)
    attack._request_certificate_ces()
    assert saved == []
    assert attack.adcs_relay.attacked_targets == ["ESSOS\\missandei"]


def test_ces_attack_unauthorized_does_not_save(monkeypatch: pytest.MonkeyPatch):
    saved = _record_saves(monkeypatch)
    _make_attack(lambda r: httpx.Response(401))._request_certificate_ces()
    assert saved == []


def test_ces_attack_pending_does_not_save(monkeypatch: pytest.MonkeyPatch):
    saved = _record_saves(monkeypatch)
    _make_attack(
        lambda r: httpx.Response(200, content=_rstr(disposition="Pending"))
    )._request_certificate_ces()
    assert saved == []


def test_ces_attack_non_xml_does_not_save(monkeypatch: pytest.MonkeyPatch):
    saved = _record_saves(monkeypatch)
    _make_attack(
        lambda r: httpx.Response(200, content=b"<html>nope")
    )._request_certificate_ces()
    assert saved == []


def test_ces_attack_uses_encoded_path(monkeypatch: pytest.MonkeyPatch):
    _record_saves(monkeypatch)
    seen: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["path"] = request.url.raw_path.decode()
        return httpx.Response(401)

    _make_attack(
        handler, to_url="https://h/My%20CA_CES_Kerberos/service.svc/CES"
    )._request_certificate_ces()
    assert seen["path"] == "/My%20CA_CES_Kerberos/service.svc/CES"


def test_ces_attack_default_template_machine(monkeypatch: pytest.MonkeyPatch):
    _record_saves(monkeypatch)
    seen: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["body"] = request.content
        return httpx.Response(401)

    _make_attack(handler, template=None, username="WS01$")._request_certificate_ces()
    assert (
        b'<ContextItem Name="CertificateTemplate"><Value>Machine</Value></ContextItem>'
        in seen["body"]
    )


def test_ces_attack_dispatch(monkeypatch: pytest.MonkeyPatch):
    attack = _make_attack(lambda r: httpx.Response(401))
    called: List[int] = []
    monkeypatch.setattr(attack, "_request_certificate_ces", lambda: called.append(1))
    attack._run()
    assert called == [1]


class _NoopConfig:
    def __getattr__(self, name: str) -> Any:
        return lambda *a: None


@pytest.fixture
def stub_relay_server(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(relay_module, "SMBRelayServer", lambda config: object())
    monkeypatch.setattr(
        relay_module, "TargetsProcessor", lambda *a, **k: SimpleNamespace()
    )
    monkeypatch.setattr(relay_module, "NTLMRelayxConfig", _NoopConfig)


def test_relay_init_ces_mode(stub_relay_server: None):
    r = Relay(target=CES_URL, ces=True, template="User")
    assert r.target == CES_URL
    assert r.base_url == "https://braavos.essos.local"
    assert r.ces_to_url == CES_URL


def test_relay_init_ces_rejects_retrieve(stub_relay_server: None):
    with pytest.raises(SystemExit):
        Relay(target=CES_URL, ces=True, retrieve=5)


def test_relay_init_ces_rejects_enum_templates(stub_relay_server: None):
    with pytest.raises(SystemExit):
        Relay(target=CES_URL, ces=True, enum_templates=True)


@pytest.mark.parametrize("bad", ["", "ftp://h/x"])
def test_build_ces_target_rejects_invalid(bad: str):
    with pytest.raises(ValueError):
        Relay._build_ces_target(bad)


@pytest.mark.parametrize("bad", ["", "ftp://h/x"])
def test_relay_init_ces_rejects_invalid_target(stub_relay_server: None, bad: str):
    with pytest.raises(SystemExit):
        Relay(target=bad, ces=True)


def test_relay_init_ces_rejects_rpc_target(stub_relay_server: None):
    with pytest.raises(SystemExit):
        Relay(target="rpc://h", ca="X", ces=True)


@pytest.mark.parametrize("session_timeout,expected", [(None, None), (5, 60)])
def test_ces_attack_timeout_override(
    monkeypatch: pytest.MonkeyPatch, session_timeout: Optional[float], expected: Any
):
    _record_saves(monkeypatch)
    seen: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["read"] = request.extensions["timeout"]["read"]
        return httpx.Response(401)

    attack = _make_attack(handler, session_timeout=session_timeout)
    attack._request_certificate_ces()
    assert seen["read"] == expected


@pytest.mark.parametrize(
    "exc",
    [
        httpx.ReadTimeout("timed out"),
        httpx.ConnectError("connection reset"),
    ],
)
def test_ces_attack_network_error_finishes_run(
    monkeypatch: pytest.MonkeyPatch, exc: Exception
):
    saved = _record_saves(monkeypatch)

    def handler(request: httpx.Request) -> httpx.Response:
        raise exc

    attack = _make_attack(handler)
    attack._request_certificate_ces()
    assert saved == []
    assert attack.adcs_relay.attacked_targets == ["ESSOS\\missandei"]


def test_ces_attack_missing_target_url_finishes_run(monkeypatch: pytest.MonkeyPatch):
    saved = _record_saves(monkeypatch)
    attack = _make_attack(lambda r: httpx.Response(401))
    attack.adcs_relay.ces_to_url = None  # type: ignore[attr-defined]
    attack._request_certificate_ces()
    assert saved == []
    assert attack.adcs_relay.attacked_targets == ["ESSOS\\missandei"]
