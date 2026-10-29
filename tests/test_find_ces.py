from types import SimpleNamespace
from typing import Any, Callable

import httpx

from certipy.commands.find import Find

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
