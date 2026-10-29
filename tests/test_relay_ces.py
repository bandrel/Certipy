import argparse

from certipy.commands.parsers import relay as relay_parser
from certipy.commands.relay import Relay


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
