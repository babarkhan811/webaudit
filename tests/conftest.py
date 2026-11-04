"""Real local servers for the tests: plain HTTP, TLS, and one that never answers."""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import ssl
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from webaudit.checks import select_checks
from webaudit.config import AuditConfig
from webaudit.engine import audit_site
from webaudit.targets import parse_target

HTML = [("Content-Type", "text/html; charset=utf-8")]


@dataclass
class Site:
    url: str
    port: int
    requests: list[str] = field(default_factory=list)


def _start(routes, catch_all, tls_context=None):
    site_requests: list[str] = []

    class Handler(BaseHTTPRequestHandler):
        def _serve(self, send_body: bool) -> None:
            site_requests.append(self.path)
            status, headers, body = routes.get(self.path, catch_all)
            self.send_response_only(status)
            for name, value in headers:
                self.send_header(name, value)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            if send_body:
                self.wfile.write(body)

        def do_GET(self):
            self._serve(True)

        def do_HEAD(self):
            self._serve(False)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    if tls_context:
        server.socket = tls_context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]
    scheme = "https" if tls_context else "http"
    return server, Site(f"{scheme}://127.0.0.1:{port}/", port, site_requests)


@pytest.fixture
def make_site():
    servers = []

    def factory(routes=None, catch_all=(404, HTML, b"<html>not found</html>"), tls_context=None):
        server, site = _start(routes or {}, catch_all, tls_context)
        servers.append(server)
        return site

    yield factory
    for server in servers:
        server.shutdown()
        server.server_close()


@pytest.fixture
def hanging_url():
    """A server that accepts connections and then never sends a byte."""
    listener = socket.create_server(("127.0.0.1", 0))
    held: list[socket.socket] = []

    def accept_forever():
        try:
            while True:
                held.append(listener.accept()[0])
        except OSError:
            pass

    threading.Thread(target=accept_forever, daemon=True).start()
    yield f"http://127.0.0.1:{listener.getsockname()[1]}/"
    listener.close()
    for connection in held:
        connection.close()


def audit(url: str, only: list[str], **settings):
    settings = {"retries": 0, "request_timeout": 2.0, **settings}
    return asyncio.run(
        audit_site(parse_target(url), AuditConfig(**settings), select_checks(only))
    )


def titles(report) -> set[str]:
    return {finding.title for finding in report.findings}


class CertificateAuthority:
    def __init__(self, directory):
        self.directory = directory
        self.key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "webaudit test CA")])
        now = datetime.now(UTC)
        self.certificate = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(self.key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=3650))
            .not_valid_after(now + timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(self.key.public_key()), critical=False)
            .sign(self.key, hashes.SHA256())
        )
        self.path = directory / "ca.pem"
        self.path.write_bytes(self.certificate.public_bytes(serialization.Encoding.PEM))

    def server_context(self, *, ip="127.0.0.1", days_left=90, self_signed=False) -> ssl.SSLContext:
        key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test site")])
        now = datetime.now(UTC)
        expiry = now + timedelta(days=days_left)
        issuer = subject if self_signed else self.certificate.subject
        certificate = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(expiry - timedelta(days=365))
            .not_valid_after(expiry)
            .add_extension(
                x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(ip))]),
                critical=False,
            )
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
            )
            .sign(key if self_signed else self.key, hashes.SHA256())
        )
        pem = self.directory / f"leaf-{certificate.serial_number}.pem"
        pem.write_bytes(
            certificate.public_bytes(serialization.Encoding.PEM)
            + key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(pem)
        return context


@pytest.fixture
def ca(tmp_path):
    return CertificateAuthority(tmp_path)
