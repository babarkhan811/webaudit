"""TLS certificate validity, expiry and strength."""

from __future__ import annotations

import asyncio
import ssl
import warnings
from contextlib import suppress
from datetime import UTC, datetime

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa

from webaudit.checks.base import register
from webaudit.context import SiteContext, verifying_context
from webaudit.models import CheckResult, Severity

# OpenSSL X509_V_ERR codes that map to a specific finding.
_VERIFY_FINDINGS = {
    18: ("Self-signed certificate", Severity.HIGH),
    19: ("Self-signed certificate in chain", Severity.HIGH),
    20: ("Certificate issuer is not trusted", Severity.HIGH),
    21: ("Incomplete certificate chain", Severity.HIGH),
    62: ("Certificate does not match hostname", Severity.CRITICAL),
    64: ("Certificate does not match IP address", Severity.CRITICAL),
}
_EXPIRED = 10
_LEGACY_PROTOCOLS = {"SSLv3", "TLSv1", "TLSv1.1"}
_WEAK_HASHES = {"md5", "sha1"}


def _inspection_context() -> ssl.SSLContext:
    """Accept anything, so that broken or outdated servers can still be described."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        context.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
    with suppress(ssl.SSLError):
        context.set_ciphers("DEFAULT:@SECLEVEL=0")
    return context


async def _handshake(
    host: str, port: int, context: ssl.SSLContext, timeout: float
) -> tuple[bytes, str, str]:
    async with asyncio.timeout(timeout):
        _, writer = await asyncio.open_connection(
            host, port, ssl=context, server_hostname=host
        )
    try:
        tls = writer.get_extra_info("ssl_object")
        return tls.getpeercert(binary_form=True), tls.version(), tls.cipher()[0]
    finally:
        writer.close()
        with suppress(OSError, TimeoutError, ssl.SSLError):
            await asyncio.wait_for(writer.wait_closed(), 2)


def describe_certificate(der: bytes) -> dict:
    cert = x509.load_der_x509_certificate(der)
    try:
        names = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        sans = [str(name.value) for name in names]
    except x509.ExtensionNotFound:
        sans = []
    key = cert.public_key()
    hash_algorithm = cert.signature_hash_algorithm
    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "serial": format(cert.serial_number, "x"),
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": cert.not_valid_after_utc.isoformat(),
        "sans": sans,
        "signature_hash": hash_algorithm.name if hash_algorithm else None,
        "rsa_key_bits": key.key_size if isinstance(key, rsa.RSAPublicKey) else None,
    }


def _assess_certificate(result: CheckResult, cert: dict) -> None:
    now = datetime.now(UTC)
    not_before = datetime.fromisoformat(cert["not_before"])
    not_after = datetime.fromisoformat(cert["not_after"])
    days = (not_after - now).days
    result.data["days_until_expiry"] = days
    renew = "Renew the certificate and automate renewal."

    if not_after < now:
        result.add(
            Severity.CRITICAL,
            "TLS certificate has expired",
            f"The certificate expired on {not_after.date()}.",
            renew,
        )
    elif days <= 14:
        result.add(
            Severity.HIGH,
            "TLS certificate expires very soon",
            f"The certificate expires in {days} days.",
            renew,
        )
    elif days <= 30:
        result.add(
            Severity.MEDIUM,
            "TLS certificate expires soon",
            f"The certificate expires in {days} days.",
            renew,
        )
    if not_before > now:
        result.add(
            Severity.HIGH,
            "TLS certificate is not valid yet",
            f"The certificate becomes valid on {not_before.date()}.",
            "Check the certificate dates and the server clock.",
        )
    if cert["signature_hash"] in _WEAK_HASHES:
        result.add(
            Severity.HIGH,
            "Weak certificate signature",
            f"The certificate is signed with {cert['signature_hash']}.",
            "Reissue the certificate with SHA-256 or stronger.",
        )
    if cert["rsa_key_bits"] and cert["rsa_key_bits"] < 2048:
        result.add(
            Severity.HIGH,
            "Weak RSA key",
            f"The certificate uses a {cert['rsa_key_bits']}-bit RSA key.",
            "Reissue the certificate with a 2048-bit or larger key.",
        )


def _report_unavailable(result: CheckResult, port: int, exc: Exception) -> None:
    result.data["trusted"] = False
    result.add(
        Severity.HIGH,
        "HTTPS is not available",
        f"No TLS handshake on port {port}: {type(exc).__name__}.",
        "Serve the site over HTTPS with a valid certificate.",
    )


@register("tls", "Certificate validity, expiry, hostname match and strength")
async def run(ctx: SiteContext, result: CheckResult) -> None:
    target = ctx.target
    port = target.port if target.scheme == "https" else 443
    timeout = ctx.config.request_timeout
    result.data.update(host=target.host, port=port)

    verify_code = None
    try:
        await _handshake(
            target.host, port, verifying_context(ctx.config.ca_bundle), timeout
        )
        result.data["trusted"] = True
    except ssl.SSLCertVerificationError as exc:
        verify_code = exc.verify_code
        result.data.update(trusted=False, verify_error=exc.verify_message)
    except ssl.SSLError:
        pass  # possibly a legacy server: the inspection handshake below can tell
    except (OSError, TimeoutError) as exc:
        _report_unavailable(result, port, exc)  # nothing is listening, so don't retry
        return

    try:
        der, version, cipher = await _handshake(
            target.host, port, _inspection_context(), timeout
        )
    except (OSError, TimeoutError, ssl.SSLError) as exc:
        _report_unavailable(result, port, exc)
        return

    certificate = describe_certificate(der)
    result.data.update(protocol=version, cipher=cipher, certificate=certificate)
    _assess_certificate(result, certificate)

    if version in _LEGACY_PROTOCOLS:
        result.add(
            Severity.HIGH,
            "Outdated TLS protocol negotiated",
            f"The server's best offer was {version}.",
            "Enable TLS 1.2 and 1.3, and disable older versions.",
        )
    if verify_code in _VERIFY_FINDINGS:
        title, severity = _VERIFY_FINDINGS[verify_code]
        result.add(
            severity,
            title,
            result.data["verify_error"],
            "Install a certificate from a trusted CA that covers this hostname.",
        )
    elif verify_code not in (None, _EXPIRED):
        result.add(
            Severity.HIGH,
            "Certificate verification failed",
            result.data["verify_error"],
            "Check the certificate and its chain.",
        )
