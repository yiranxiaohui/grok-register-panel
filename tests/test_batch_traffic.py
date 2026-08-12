#!/usr/bin/env python3
from __future__ import annotations

import os
import base64
import socket
import socketserver
import stat
import sys
import tempfile
import threading
import time
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import batch_traffic


def _read_headers(sock: socket.socket) -> bytes:
    data = bytearray()
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(8192)
        if not chunk:
            break
        data.extend(chunk)
    return bytes(data)


class FakeUpstreamHandler(socketserver.BaseRequestHandler):
    def handle(self):
        request = _read_headers(self.request)
        self.server.requests.append(request)  # type: ignore[attr-defined]
        if request.startswith(b"CONNECT "):
            self.request.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            payload = self.request.recv(4)
            if payload == b"ping":
                self.request.sendall(b"pong")
            return
        body = b"hello"
        self.request.sendall(
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\n"
            + body
        )


class FakeUpstream(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("unexpected end of SOCKS5 test connection")
        data.extend(chunk)
    return bytes(data)


class FakeSocksHandler(socketserver.BaseRequestHandler):
    def handle(self):
        version, method_count = _recv_exact(self.request, 2)
        methods = _recv_exact(self.request, method_count)
        assert version == 5 and methods == b"\x02"
        self.request.sendall(b"\x05\x02")

        auth_version, username_size = _recv_exact(self.request, 2)
        username = _recv_exact(self.request, username_size)
        password_size = _recv_exact(self.request, 1)[0]
        password = _recv_exact(self.request, password_size)
        self.server.credentials.append((username, password))  # type: ignore[attr-defined]
        assert auth_version == 1
        self.request.sendall(b"\x01\x00")

        version, command, reserved, address_type = _recv_exact(self.request, 4)
        assert (version, command, reserved) == (5, 1, 0)
        if address_type == 1:
            host = socket.inet_ntop(socket.AF_INET, _recv_exact(self.request, 4))
        elif address_type == 4:
            host = socket.inet_ntop(socket.AF_INET6, _recv_exact(self.request, 16))
        else:
            host_size = _recv_exact(self.request, 1)[0]
            host = _recv_exact(self.request, host_size).decode("idna")
        port = int.from_bytes(_recv_exact(self.request, 2), "big")
        self.server.targets.append((host, port))  # type: ignore[attr-defined]
        self.request.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00")

        if port == 443:
            if self.request.recv(4) == b"ping":
                self.request.sendall(b"pong")
            return
        request = _read_headers(self.request)
        self.server.requests.append(request)  # type: ignore[attr-defined]
        self.request.sendall(
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello"
        )


def _connect_to_meter(url: str) -> socket.socket:
    parsed = urlparse(url)
    return socket.create_connection((parsed.hostname, parsed.port), timeout=5)


def _meter_auth_header(url: str) -> bytes:
    parsed = urlparse(url)
    token = base64.b64encode(
        f"{parsed.username}:{parsed.password}".encode("utf-8")
    ).decode("ascii")
    return f"Proxy-Authorization: Basic {token}\r\n".encode("ascii")


def test_http_connect_metering_and_private_state():
    previous_file = os.environ.get(batch_traffic.TRAFFIC_FILE_ENV)
    previous_id = os.environ.get(batch_traffic.BATCH_ID_ENV)
    upstream = FakeUpstream(("127.0.0.1", 0), FakeUpstreamHandler)
    upstream.requests = []
    thread = threading.Thread(target=upstream.serve_forever, daemon=True)
    thread.start()
    try:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "batch_traffic.json"
            batch_traffic.initialize_batch(path, "batch-a", target=2, workers=1)
            os.environ[batch_traffic.TRAFFIC_FILE_ENV] = str(path)
            os.environ[batch_traffic.BATCH_ID_ENV] = "batch-a"
            proxy = (
                f"http://example-user:example-pass@127.0.0.1:{upstream.server_address[1]}"
            )
            meter = batch_traffic.meter_proxy_url(proxy)
            assert meter.startswith("http://meter:")

            unauthorized = _connect_to_meter(meter)
            unauthorized.sendall(
                b"GET http://example.test/ HTTP/1.1\r\nHost: example.test\r\n\r\n"
            )
            assert b" 407 " in _read_headers(unauthorized).split(b"\r\n", 1)[0]
            unauthorized.close()

            client = _connect_to_meter(meter)
            client.sendall(
                b"GET http://example.test/resource HTTP/1.1\r\n"
                b"Host: example.test\r\n"
                + _meter_auth_header(meter)
                + b"Connection: close\r\n\r\n"
            )
            response = bytearray()
            while True:
                chunk = client.recv(8192)
                if not chunk:
                    break
                response.extend(chunk)
            client.close()
            assert response.endswith(b"hello")

            client = _connect_to_meter(meter)
            client.sendall(
                b"CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\n"
                + _meter_auth_header(meter)
                + b"\r\nping"
            )
            connect_response = _read_headers(client)
            assert b" 200 " in connect_response.split(b"\r\n", 1)[0]
            assert client.recv(4) == b"pong"
            client.close()

            batch_traffic.mark_successful_account(2)
            assert batch_traffic.read_metrics(path)["successful_accounts"] == 2
            finalized = batch_traffic.finalize_batch(path, "batch-a", 0)
            time.sleep(0.7)
            metrics = batch_traffic.read_metrics(path)
            assert metrics["batch_id"] == "batch-a"
            assert metrics["connections"] == 3
            assert metrics["active_connections"] == 0
            assert metrics["bytes_up"] > 0
            assert metrics["bytes_down"] > 0
            assert metrics["bytes_total"] == metrics["bytes_up"] + metrics["bytes_down"]
            assert metrics["metered_proxies"] == 1
            assert metrics["successful_accounts"] == 2
            state_text = path.read_text(encoding="utf-8")
            assert "example-user" not in state_text
            assert "example-pass" not in state_text
            assert urlparse(meter).password not in state_text
            assert stat.S_IMODE(path.stat().st_mode) == 0o600
            assert all(b"Proxy-Authorization: Basic " in item for item in upstream.requests)

            assert finalized["running"] is False
            assert finalized["exit_code"] == 0
            assert metrics["running"] is False

            reset = batch_traffic.initialize_batch(path, "batch-b", target=3, workers=2)
            assert reset["batch_id"] == "batch-b"
            assert reset["bytes_total"] == 0
            assert reset["connections"] == 0
            assert reset["successful_accounts"] == 0
    finally:
        batch_traffic.close_runtime()
        upstream.shutdown()
        upstream.server_close()
        thread.join(timeout=5)
        if previous_file is None:
            os.environ.pop(batch_traffic.TRAFFIC_FILE_ENV, None)
        else:
            os.environ[batch_traffic.TRAFFIC_FILE_ENV] = previous_file
        if previous_id is None:
            os.environ.pop(batch_traffic.BATCH_ID_ENV, None)
        else:
            os.environ[batch_traffic.BATCH_ID_ENV] = previous_id


def test_authenticated_socks5_is_bridged_to_local_http_proxy():
    previous_file = os.environ.get(batch_traffic.TRAFFIC_FILE_ENV)
    previous_id = os.environ.get(batch_traffic.BATCH_ID_ENV)
    upstream = FakeUpstream(("127.0.0.1", 0), FakeSocksHandler)
    upstream.credentials = []
    upstream.targets = []
    upstream.requests = []
    thread = threading.Thread(target=upstream.serve_forever, daemon=True)
    thread.start()
    try:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "batch_traffic.json"
            batch_traffic.initialize_batch(path, "batch-socks", target=1, workers=1)
            os.environ[batch_traffic.TRAFFIC_FILE_ENV] = str(path)
            os.environ[batch_traffic.BATCH_ID_ENV] = "batch-socks"
            proxy = (
                f"socks5h://example-user:example-pass@127.0.0.1:"
                f"{upstream.server_address[1]}"
            )
            meter = batch_traffic.meter_proxy_url(proxy)
            assert meter.startswith("http://meter:")

            client = _connect_to_meter(meter)
            client.sendall(
                b"GET http://example.test/resource?q=1 HTTP/1.1\r\n"
                b"Host: example.test\r\n"
                + _meter_auth_header(meter)
                + b"Connection: close\r\n\r\n"
            )
            response = bytearray()
            while chunk := client.recv(8192):
                response.extend(chunk)
            client.close()
            assert response.endswith(b"hello")

            client = _connect_to_meter(meter)
            client.sendall(
                b"CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\n"
                + _meter_auth_header(meter)
                + b"\r\nping"
            )
            connect_response = _read_headers(client)
            assert b" 200 " in connect_response.split(b"\r\n", 1)[0]
            assert client.recv(4) == b"pong"
            client.close()

            batch_traffic.close_runtime()
            metrics = batch_traffic.read_metrics(path)
            assert metrics["metered_proxies"] == 1
            assert metrics["unmetered_proxies"] == 0
            assert metrics["connections"] == 2
            assert upstream.credentials == [
                (b"example-user", b"example-pass"),
                (b"example-user", b"example-pass"),
            ]
            assert upstream.targets == [("example.test", 80), ("example.test", 443)]
            assert upstream.requests[0].startswith(
                b"GET /resource?q=1 HTTP/1.1\r\n"
            )
            assert b"Proxy-Authorization" not in upstream.requests[0]
            state_text = path.read_text(encoding="utf-8")
            assert "example-user" not in state_text
            assert "example-pass" not in state_text
            assert urlparse(meter).password not in state_text
    finally:
        batch_traffic.close_runtime()
        upstream.shutdown()
        upstream.server_close()
        thread.join(timeout=5)
        if previous_file is None:
            os.environ.pop(batch_traffic.TRAFFIC_FILE_ENV, None)
        else:
            os.environ[batch_traffic.TRAFFIC_FILE_ENV] = previous_file
        if previous_id is None:
            os.environ.pop(batch_traffic.BATCH_ID_ENV, None)
        else:
            os.environ[batch_traffic.BATCH_ID_ENV] = previous_id


def test_batch_history_is_private_idempotent_and_summarized():
    with tempfile.TemporaryDirectory() as temp:
        history_path = Path(temp) / "log" / "batch_traffic_history.json"
        first = {
            "batch_id": "batch-a",
            "started_at": "malformed timestamp",
            "bytes_up": 300,
            "bytes_down": 700,
            "successful_accounts": 2,
            "target": 3,
            "workers": 1,
            "exit_code": 0,
        }
        assert batch_traffic.archive_batch(history_path, first)
        assert batch_traffic.archive_batch(history_path, first)
        assert stat.S_IMODE(history_path.stat().st_mode) == 0o600

        second = {
            "batch_id": "batch-b",
            "started_at": 20,
            "finished_at": 30,
            "bytes_up": 1_000,
            "bytes_down": 2_000,
            "successful_accounts": 3,
            "target": 4,
            "workers": 2,
            "exit_code": 0,
        }
        assert batch_traffic.archive_batch(history_path, second)
        history = batch_traffic.read_history(history_path)
        assert len(history["batches"]) == 2

        current = {
            "batch_id": "batch-c",
            "started_at": 40,
            "bytes_up": 500,
            "bytes_down": 500,
            "successful_accounts": 1,
        }
        summary = batch_traffic.read_summary(history_path, current)
        assert summary == {
            "batch_count": 3,
            "completed_batch_count": 2,
            "includes_current": True,
            "total_bytes": 5_000,
            "successful_accounts": 6,
            "bytes_per_batch": 1_666,
            "bytes_per_success": 833,
        }

        archived_summary = batch_traffic.read_summary(history_path, second)
        assert archived_summary["batch_count"] == 2
        assert archived_summary["includes_current"] is False

        assert not batch_traffic.archive_batch(
            history_path,
            {"batch_id": "zero-byte", "successful_accounts": 1},
        )
        assert len(batch_traffic.read_history(history_path)["batches"]) == 2


if __name__ == "__main__":
    test_http_connect_metering_and_private_state()
    test_authenticated_socks5_is_bridged_to_local_http_proxy()
    test_batch_history_is_private_idempotent_and_summarized()
    print("OK batch traffic")
