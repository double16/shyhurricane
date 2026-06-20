import argparse
import socket

import pytest

import shyhurricane.pick_nic as pick_nic


class FakeSocket:
    def __init__(self, family, fail=False):
        self.family = family
        self.fail = fail
        self.closed = False

    def connect(self, sockaddr):
        if self.fail:
            raise OSError("unreachable")

    def getsockname(self):
        return ("192.0.2.10", 12345)

    def close(self):
        self.closed = True


def test_pick_local_addr_returns_first_connectable_socket(monkeypatch):
    sockets = iter([FakeSocket(socket.AF_INET, fail=True), FakeSocket(socket.AF_INET)])
    monkeypatch.setattr(
        pick_nic.socket,
        "getaddrinfo",
        lambda *args: [
            (socket.AF_INET, socket.SOCK_DGRAM, 0, "", ("198.51.100.1", 53)),
            (socket.AF_INET, socket.SOCK_DGRAM, 0, "", ("198.51.100.2", 53)),
        ],
    )
    monkeypatch.setattr(pick_nic.socket, "socket", lambda family, socktype: next(sockets))

    assert pick_nic.pick_local_addr("example.com") == ("192.0.2.10", socket.AF_INET)


def test_pick_local_addr_raises_when_all_sockets_fail(monkeypatch):
    monkeypatch.setattr(
        pick_nic.socket,
        "getaddrinfo",
        lambda *args: [(socket.AF_INET, socket.SOCK_DGRAM, 0, "", ("198.51.100.1", 53))],
    )
    monkeypatch.setattr(pick_nic.socket, "socket", lambda family, socktype: FakeSocket(family, fail=True))

    with pytest.raises(OSError, match="Could not determine local address"):
        pick_nic.pick_local_addr("example.com")


class Addr:
    def __init__(self, family, address):
        self.family = family
        self.address = address


def test_map_ip_to_interfaces_handles_no_psutil_and_matches(monkeypatch):
    monkeypatch.setattr(pick_nic, "psutil", None)
    assert pick_nic.map_ip_to_interfaces("192.0.2.10", socket.AF_INET) == []

    class Psutil:
        @staticmethod
        def net_if_addrs():
            return {
                "en1": [Addr(socket.AF_INET, "192.0.2.10")],
                "en0": [Addr(socket.AF_INET, "192.0.2.10")],
                "lo0": [Addr(socket.AF_INET6, "::1")],
            }

    monkeypatch.setattr(pick_nic, "psutil", Psutil)
    assert pick_nic.map_ip_to_interfaces("192.0.2.10", socket.AF_INET) == ["en0", "en1"]


def test_main_prints_interface_and_unknown_messages(monkeypatch, capsys):
    monkeypatch.setattr(pick_nic, "pick_local_addr", lambda destination, port: ("192.0.2.10", socket.AF_INET))
    monkeypatch.setattr(pick_nic, "map_ip_to_interfaces", lambda local_ip, family: ["en0"])
    monkeypatch.setattr(argparse.ArgumentParser, "parse_args",
                        lambda self: argparse.Namespace(destination="example.com", port=53))

    pick_nic.main()

    assert "Interface       : en0" in capsys.readouterr().out

    monkeypatch.setattr(pick_nic, "map_ip_to_interfaces", lambda local_ip, family: [])
    monkeypatch.setattr(pick_nic, "psutil", None)
    pick_nic.main()
    assert "install psutil" in capsys.readouterr().out
