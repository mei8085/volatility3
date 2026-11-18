"""Tests for integrity-checked remote ISF retrieval.

The tests exercise the download/cache layer (``ResourceAccessor``) and the
remote identifier listing (``RemoteIdentifierFormat``) without a memory image:

* legitimate sources are accepted,
* a certificate error is rejected (never retried without verification),
* substituted content is rejected,
* truncated content is rejected,
* a cache hit that conflicts with the expected content is rejected instead of
  being parsed,
* nothing rejected leaves a reusable half file behind,
* an offline run can still use previously verified cached content,
* configured local mirrors keep working.

The HTTP(S) servers are local, in-process ``http.server`` instances, so no
network access is required.  The TLS server uses a certificate generated on the
fly (see ``_generate_certificate``); tests that need it call
``pytest.importorskip`` so a machine without ``cryptography`` or ``openssl``
simply skips rather than fails.
"""

import base64
import contextlib
import hashlib
import http.server
import json
import shutil
import ssl
import subprocess
import threading
from pathlib import Path

import pytest

import volatility3.plugins.isfinfo

from volatility3.framework import constants, exceptions
from volatility3.framework.automagic import symbol_cache
from volatility3.framework.layers import resources
from volatility3.framework.symbols import intermed

PAYLOAD = b'{"metadata": {"format": "6.2.0"}, "symbols": {}, "base_types": {}}'
SUBSTITUTED = (
    b'{"metadata": {"format": "6.2.0"}, "symbols": {}, "base_types": {"evil": {}}}'
)
TRUNCATED = PAYLOAD[: len(PAYLOAD) // 2]


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@pytest.fixture(autouse=True)
def isolated_cache(tmp_path, monkeypatch):
    """Redirects the cache and forgets all in-memory expectations."""
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    monkeypatch.setattr(constants, "CACHE_PATH", str(cache_dir))
    resources.reset_expectations()
    yield cache_dir
    resources.reset_expectations()


class _Server:
    """A tiny HTTP server whose responses can be changed between requests."""

    def __init__(self, tls_context=None):
        self.content = PAYLOAD
        self.status = 200
        self.declared_length = None
        self.path = "/symbols.json"
        self.requests = 0
        handler = self._make_handler()
        self.httpd = http.server.HTTPServer(("127.0.0.1", 0), handler)
        if tls_context is not None:
            self.httpd.socket = tls_context.wrap_socket(
                self.httpd.socket, server_side=True
            )
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def _make_handler(self):
        server = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                server.requests += 1
                self.send_response(server.status)
                length = (
                    server.declared_length
                    if server.declared_length is not None
                    else len(server.content)
                )
                self.send_header("Content-Length", str(length))
                self.end_headers()
                self.wfile.write(server.content)

            def log_message(self, *args):
                pass

        return Handler

    @property
    def url(self):
        scheme = "https" if isinstance(self.httpd.socket, ssl.SSLSocket) else "http"
        host, port = self.httpd.server_address[:2]
        return f"{scheme}://{host}:{port}{self.path}"

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def server():
    srv = _Server()
    yield srv
    srv.close()


def _fetch(url, **kwargs):
    with resources.ResourceAccessor(**kwargs).open(url) as fp:
        return fp.read()


# ---------------------------------------------------------------------------
# Legitimate sources
# ---------------------------------------------------------------------------


def test_legitimate_source_is_accepted(server):
    assert _fetch(server.url) == PAYLOAD
    assert server.requests == 1


def test_legitimate_source_with_matching_digest_is_accepted(server):
    assert _fetch(server.url, expected_hash=_sha256(PAYLOAD)) == PAYLOAD


def test_second_fetch_uses_cache_without_contacting_the_server(server):
    assert _fetch(server.url) == PAYLOAD
    assert _fetch(server.url) == PAYLOAD
    assert server.requests == 1


# ---------------------------------------------------------------------------
# Substituted content
# ---------------------------------------------------------------------------


def test_substituted_content_is_rejected(server):
    resources.register_expected_hash(server.url, _sha256(PAYLOAD))
    server.content = SUBSTITUTED
    with pytest.raises(exceptions.ResourceIntegrityError):
        _fetch(server.url)


def test_substituted_content_leaves_no_cache_file(server, isolated_cache):
    resources.register_expected_hash(server.url, _sha256(PAYLOAD))
    server.content = SUBSTITUTED
    with pytest.raises(exceptions.ResourceIntegrityError):
        _fetch(server.url)
    assert not list(isolated_cache.glob("data_*.cache"))
    assert not list(isolated_cache.glob("*.part"))


def test_conflicting_cache_hit_is_rejected_and_discarded(server, isolated_cache):
    # Establish a verified cache entry
    resources.register_expected_hash(server.url, _sha256(PAYLOAD))
    assert _fetch(server.url) == PAYLOAD
    cache_file = next(isolated_cache.glob("data_*.cache"))
    # Tamper with the cached content behind the accessor's back
    cache_file.write_bytes(SUBSTITUTED)
    # Same expectation: the cached content no longer matches, so the accessor
    # must reject it (and leave no reusable copy behind) rather than parse it.
    with pytest.raises(exceptions.ResourceIntegrityError):
        _fetch(server.url)
    assert not cache_file.exists()
    assert not list(isolated_cache.glob("*.part"))


def test_conflicting_cache_hit_with_wrong_download_is_rejected(server, isolated_cache):
    resources.register_expected_hash(server.url, _sha256(PAYLOAD))
    assert _fetch(server.url) == PAYLOAD
    cache_file = next(isolated_cache.glob("data_*.cache"))
    cache_file.write_bytes(SUBSTITUTED)
    server.content = SUBSTITUTED
    with pytest.raises(exceptions.ResourceIntegrityError):
        _fetch(server.url)
    assert not cache_file.exists()
    assert not list(isolated_cache.glob("*.part"))


# ---------------------------------------------------------------------------
# Truncation
# ---------------------------------------------------------------------------


def test_truncated_download_is_rejected(server, isolated_cache):
    server.content = TRUNCATED
    server.declared_length = len(PAYLOAD)
    with pytest.raises(exceptions.ResourceIntegrityError):
        _fetch(server.url)
    assert not list(isolated_cache.glob("data_*.cache"))
    assert not list(isolated_cache.glob("*.part"))


def test_zero_length_body_is_rejected(server, isolated_cache):
    server.content = b""
    server.declared_length = len(PAYLOAD)
    with pytest.raises(exceptions.ResourceIntegrityError):
        _fetch(server.url)
    assert not list(isolated_cache.glob("data_*.cache"))


def test_truncated_content_failing_digest_is_rejected(server, isolated_cache):
    resources.register_expected_hash(server.url, _sha256(PAYLOAD))
    server.content = TRUNCATED
    server.declared_length = len(TRUNCATED)
    with pytest.raises(exceptions.ResourceIntegrityError):
        _fetch(server.url)
    assert not list(isolated_cache.glob("data_*.cache"))


# ---------------------------------------------------------------------------
# Offline cache behaviour
# ---------------------------------------------------------------------------


def test_offline_run_uses_previously_verified_cache(server, monkeypatch):
    resources.register_expected_hash(server.url, _sha256(PAYLOAD))
    assert _fetch(server.url) == PAYLOAD
    url = server.url
    server.close()

    monkeypatch.setattr(constants, "OFFLINE", True)
    try:
        assert _fetch(url) == PAYLOAD
    finally:
        monkeypatch.setattr(constants, "OFFLINE", False)


def test_offline_run_without_cache_raises_offline(monkeypatch):
    monkeypatch.setattr(constants, "OFFLINE", True)
    try:
        with pytest.raises(exceptions.OfflineException):
            _fetch("http://127.0.0.1:1/never.json")
    finally:
        monkeypatch.setattr(constants, "OFFLINE", False)


def test_offline_run_rejects_tampered_cache(server, monkeypatch, isolated_cache):
    resources.register_expected_hash(server.url, _sha256(PAYLOAD))
    assert _fetch(server.url) == PAYLOAD
    cache_file = next(isolated_cache.glob("data_*.cache"))
    cache_file.write_bytes(SUBSTITUTED)
    url = server.url
    server.close()

    monkeypatch.setattr(constants, "OFFLINE", True)
    try:
        with pytest.raises(exceptions.ResourceIntegrityError):
            _fetch(url)
    finally:
        monkeypatch.setattr(constants, "OFFLINE", False)
    assert not cache_file.exists()


# ---------------------------------------------------------------------------
# Local mirrors
# ---------------------------------------------------------------------------


def test_local_file_mirror_is_accepted(tmp_path):
    mirror = tmp_path / "mirror.json"
    mirror.write_bytes(PAYLOAD)
    assert _fetch(mirror.as_uri()) == PAYLOAD


def test_local_file_mirror_with_digest_is_enforced(tmp_path):
    mirror = tmp_path / "mirror.json"
    mirror.write_bytes(SUBSTITUTED)
    with pytest.raises(exceptions.ResourceIntegrityError):
        _fetch(
            mirror.as_uri(),
            expected_hash=_sha256(PAYLOAD),
        )


# ---------------------------------------------------------------------------
# Certificate errors
# ---------------------------------------------------------------------------


def _generate_certificate(directory: Path) -> tuple[Path, Path]:
    if shutil.which("openssl") is None:
        pytest.skip("openssl is required to generate a test certificate")
    key = directory / "key.pem"
    cert = directory / "cert.pem"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            str(key),
            "-out",
            str(cert),
            "-days",
            "3650",
            "-nodes",
            "-subj",
            "/CN=127.0.0.1",
            "-addext",
            "subjectAltName=IP:127.0.0.1,DNS:localhost",
        ],
        check=True,
        capture_output=True,
    )
    return cert, key


@pytest.fixture
def tls_server(tmp_path):
    pytest.importorskip("cryptography")
    cert, key = _generate_certificate(tmp_path)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(cert), str(key))
    srv = _Server(tls_context=context)
    srv.certificate = cert
    yield srv
    srv.close()


def test_certificate_error_is_rejected_not_retried(tls_server):
    # The self-signed certificate is not in the default trust store: the
    # download must fail, and must not be silently retried without verification.
    with pytest.raises(exceptions.ResourceIntegrityError):
        _fetch(tls_server.url)
    assert tls_server.requests == 0


def test_certificate_error_does_not_go_offline(tls_server):
    before = constants.OFFLINE
    with pytest.raises(exceptions.ResourceIntegrityError):
        _fetch(tls_server.url)
    # A certificate failure is not an offline condition, so the rest of the run
    # still attempts other (legitimate) sources.
    assert constants.OFFLINE == before
    assert not list(Path(constants.CACHE_PATH).glob("data_*.cache"))


def test_configured_trusted_ca_makes_the_mirror_work(tls_server):
    context = ssl.create_default_context(cafile=str(tls_server.certificate))
    assert _fetch(tls_server.url, context=context) == PAYLOAD


def test_verified_tls_mirror_content_is_pinned(tls_server, isolated_cache):
    context = ssl.create_default_context(cafile=str(tls_server.certificate))
    resources.register_trusted_source(tls_server.url)
    assert _fetch(tls_server.url, context=context) == PAYLOAD
    # The first verified retrieval pinned the digest
    pinned = resources.get_pinned_hash(tls_server.url)
    assert pinned == ("sha256", _sha256(PAYLOAD))
    # Substitute the content; the cached copy still matches the pin, so no
    # download happens.  Remove the cache to force a re-fetch.
    for cache_file in isolated_cache.glob("data_*.cache"):
        cache_file.unlink()
    tls_server.content = SUBSTITUTED
    with pytest.raises(exceptions.ResourceIntegrityError):
        _fetch(tls_server.url, context=context)


# ---------------------------------------------------------------------------
# Digest normalisation and signature verification
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "value",
    [
        _sha256(PAYLOAD),
        f"sha256:{_sha256(PAYLOAD)}",
        {"sha256": _sha256(PAYLOAD)},
        {"algorithm": "sha256", "digest": _sha256(PAYLOAD)},
        ("sha256", _sha256(PAYLOAD)),
    ],
)
def test_expected_hash_forms_normalise(value):
    assert resources.normalize_expected_hash(value) == ("sha256", _sha256(PAYLOAD))


@pytest.mark.parametrize("value", ["md5:00", "sha256:xyz", "sha256:" + "0" * 63, 42])
def test_malformed_expected_hash_is_rejected(value):
    with pytest.raises((TypeError, ValueError)):
        resources.normalize_expected_hash(value)


def test_conflicting_expected_hashes_are_rejected():
    url = "https://example.invalid/a.json"
    resources.register_expected_hash(url, _sha256(PAYLOAD))
    with pytest.raises(exceptions.ResourceIntegrityError):
        resources.register_expected_hash(url, _sha256(SUBSTITUTED))


def test_expectations_are_reloaded_when_cache_path_changes(tmp_path, monkeypatch):
    url = "https://example.invalid/a.json"
    first = tmp_path / "first"
    first.mkdir()
    monkeypatch.setattr(constants, "CACHE_PATH", str(first))
    resources.reset_expectations()
    resources.register_expected_hash(url, _sha256(PAYLOAD))
    assert resources.get_expected_hash(url) == ("sha256", _sha256(PAYLOAD))

    second = tmp_path / "second"
    second.mkdir()
    monkeypatch.setattr(constants, "CACHE_PATH", str(second))
    # The new cache holds no expectations yet, so the old URL is not expected
    assert resources.get_expected_hash(url) is None
    resources.register_expected_hash(url, _sha256(SUBSTITUTED))
    assert resources.get_expected_hash(url) == ("sha256", _sha256(SUBSTITUTED))


def test_deferred_expectation_saves_write_once(tmp_path, monkeypatch):
    monkeypatch.setattr(constants, "CACHE_PATH", str(tmp_path))
    resources.reset_expectations()
    path = tmp_path / constants.REMOTE_INTEGRITY_FILENAME

    with resources.deferred_expectation_saves():
        for index in range(10):
            resources.register_expected_hash(
                f"https://example.invalid/{index}", f"{index:064x}"
            )
        # Nothing is flushed while the context is active
        assert not path.exists()
    assert path.exists()
    data = json.loads(path.read_text())
    assert len(data["hashes"]) == 10
    assert resources.get_expected_hash("https://example.invalid/3") == (
        "sha256",
        f"{3:064x}",
    )


def test_isfinfo_skips_a_rejected_isf(server, isolated_cache):
    IsfInfo = volatility3.plugins.isfinfo.IsfInfo

    resources.register_expected_hash(server.url, _sha256(_isf_bytes()))
    server.content = _isf_bytes().replace(
        b'"symbols": {}', b'"symbols": {"evil": {"address": 1}}'
    )

    class FakePlugin:
        config = {"isf": server.url, "filter": [], "validate": False, "live": True}

    # The plugin refuses the unverified ISF instead of emitting it
    assert list(IsfInfo._generator(FakePlugin())) == []


def _ed25519_keypair():
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private = Ed25519PrivateKey.generate()
    public_pem = private.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private, public_pem


def test_signature_verification_accepts_signed_content():
    private, public_pem = _ed25519_keypair()
    signature = private.sign(PAYLOAD)
    resources.verify_downloaded_signature(PAYLOAD, signature, public_pem)
    # A signature over different content must not verify
    with pytest.raises(exceptions.ResourceIntegrityError):
        resources.verify_downloaded_signature(SUBSTITUTED, signature, public_pem)


def test_signature_expectation_is_enforced_on_open(server):
    private, public_pem = _ed25519_keypair()
    resources.register_expected_signature(server.url, private.sign(PAYLOAD), public_pem)
    assert _fetch(server.url) == PAYLOAD

    # Substitute content but keep the old signature: rejected
    for cache_file in Path(constants.CACHE_PATH).glob("data_*.cache"):
        cache_file.unlink()
    server.content = SUBSTITUTED
    with pytest.raises(exceptions.ResourceIntegrityError):
        _fetch(server.url)


# ---------------------------------------------------------------------------
# Remote identifier listings
# ---------------------------------------------------------------------------


def test_remote_listing_v1_accepts_local_entries(tmp_path):
    mirror = tmp_path / "mirror.json"
    mirror.write_bytes(PAYLOAD)
    identifier = base64.b64encode(b"Linux version test").decode()
    listing = tmp_path / "banners.json"
    listing.write_text(
        json.dumps({"version": 1, "linux": {identifier: [mirror.as_uri()]}})
    )
    fmt = symbol_cache.RemoteIdentifierFormat(listing.as_uri())
    entries = list(fmt.process({}, operating_system="linux"))
    assert entries == [(b"Linux version test", mirror.as_uri())]


def test_remote_listing_v1_ignores_unverified_remote_entries(tmp_path):
    listing = tmp_path / "banners.json"
    identifier = base64.b64encode(b"Linux version test").decode()
    listing.write_text(
        json.dumps(
            {
                "version": 1,
                "linux": {identifier: ["http://127.0.0.1:1/plain.json"]},
            }
        )
    )
    # A nested plain-HTTP entry without a digest cannot be verified and must be
    # ignored, even though the root listing was configured by the user.
    fmt = symbol_cache.RemoteIdentifierFormat(listing.as_uri())
    fmt._is_root = False
    assert list(fmt.process({}, operating_system="linux")) == []


def test_configured_http_entry_is_accepted_and_pinned(tmp_path, server):
    identifier = base64.b64encode(b"Linux version test").decode()
    listing = tmp_path / "banners.json"
    listing.write_text(json.dumps({"version": 1, "linux": {identifier: [server.url]}}))
    fmt = symbol_cache.RemoteIdentifierFormat(listing.as_uri())
    assert list(fmt.process({}, operating_system="linux")) == [
        (b"Linux version test", server.url)
    ]
    # The configured listing is trusted, and the first retrieval pins the digest
    assert _fetch(server.url) == PAYLOAD
    assert resources.get_pinned_hash(server.url) == ("sha256", _sha256(PAYLOAD))

    # Substituted content on the same URL is rejected
    for cache_file in Path(constants.CACHE_PATH).glob("data_*.cache"):
        cache_file.unlink()
    server.content = SUBSTITUTED
    with pytest.raises(exceptions.ResourceIntegrityError):
        _fetch(server.url)


def test_remote_listing_v2_https_entry_without_digest_is_pinned(tmp_path, tls_server):
    identifier = base64.b64encode(b"Linux version test").decode()
    listing = tmp_path / "banners.json"
    listing.write_text(
        json.dumps({"version": 2, "linux": {identifier: [tls_server.url]}})
    )
    fmt = symbol_cache.RemoteIdentifierFormat(listing.as_uri())
    assert list(fmt.process({}, operating_system="linux")) == [
        (b"Linux version test", tls_server.url)
    ]
    # An HTTPS entry is accepted, but its digest must be pinned on first use so
    # content substituted later on the same URL is rejected.
    assert resources.get_expected_hash(tls_server.url) is None
    context = ssl.create_default_context(cafile=str(tls_server.certificate))
    assert _fetch(tls_server.url, context=context) == PAYLOAD
    assert resources.get_pinned_hash(tls_server.url) == (
        "sha256",
        _sha256(PAYLOAD),
    )
    for cache_file in Path(constants.CACHE_PATH).glob("data_*.cache"):
        cache_file.unlink()
    tls_server.content = SUBSTITUTED
    with pytest.raises(exceptions.ResourceIntegrityError):
        _fetch(tls_server.url, context=context)


def test_remote_listing_v2_registers_digests(tmp_path, server):
    identifier = base64.b64encode(b"Linux version test").decode()
    listing = tmp_path / "banners.json"
    listing.write_text(
        json.dumps(
            {
                "version": 2,
                "linux": {
                    identifier: [{"location": server.url, "sha256": _sha256(PAYLOAD)}]
                },
            }
        )
    )
    fmt = symbol_cache.RemoteIdentifierFormat(listing.as_uri())
    assert list(fmt.process({}, operating_system="linux")) == [
        (b"Linux version test", server.url)
    ]
    assert resources.get_expected_hash(server.url) == ("sha256", _sha256(PAYLOAD))

    # A substituted payload is now rejected
    server.content = SUBSTITUTED
    with pytest.raises(exceptions.ResourceIntegrityError):
        _fetch(server.url)


def test_signed_remote_listing_requires_trusted_key(tmp_path):
    private, public_pem = _ed25519_keypair()
    listing = tmp_path / "banners.json"
    data = {"version": 2, "linux": {}}
    payload = json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
    data["signature"] = {
        "algorithm": "ed25519",
        "signature": base64.b64encode(private.sign(payload)).decode(),
    }
    listing.write_text(json.dumps(data))

    # No configured key: a signed listing is rejected rather than trusted
    with pytest.raises(exceptions.ResourceIntegrityError):
        symbol_cache.RemoteIdentifierFormat(listing.as_uri())

    # With the configured key the listing is accepted
    fmt = symbol_cache.RemoteIdentifierFormat(
        listing.as_uri(), trusted_key=public_pem.decode()
    )
    assert list(fmt.process({}, operating_system="linux")) == []


def test_signed_remote_listing_rejects_bad_signature(tmp_path):
    private, public_pem = _ed25519_keypair()
    listing = tmp_path / "banners.json"
    data = {"version": 2, "linux": {}}
    payload = json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
    data["signature"] = {
        "algorithm": "ed25519",
        "signature": base64.b64encode(private.sign(payload + b"x")).decode(),
    }
    listing.write_text(json.dumps(data))
    with pytest.raises(exceptions.ResourceIntegrityError):
        symbol_cache.RemoteIdentifierFormat(
            listing.as_uri(), trusted_key=public_pem.decode()
        )


# ---------------------------------------------------------------------------
# End-to-end: an ISF is only parsed after it passes verification
# ---------------------------------------------------------------------------


_ISF = {
    "metadata": {
        "format": "6.2.0",
        "producer": {"name": "test", "version": "1.0.0"},
        "windows": {"pdb": {"GUID": "A" * 32, "age": 1, "database": "test.pdb"}},
    },
    "base_types": {
        "int": {"kind": "int", "size": 4, "signed": True, "endian": "little"}
    },
    "user_types": {},
    "enums": {},
    "symbols": {},
}


def _isf_bytes() -> bytes:
    return json.dumps(_ISF).encode()


def test_isf_is_not_parsed_when_content_is_substituted(server, isolated_cache):
    # Serve a valid ISF once so the accessor caches it under a fixed digest
    good = _isf_bytes()
    server.content = good
    resources.register_expected_hash(server.url, _sha256(good))
    assert _fetch(server.url) == good

    # Substitute the content and the expectation stays the same: the cached copy
    # is fine, so no download happens.  Remove it to force a retrieval, which
    # must fail before the ISF parser sees the substituted bytes.
    for cache_file in isolated_cache.glob("data_*.cache"):
        cache_file.unlink()
    server.content = good.replace(b'"symbols": {}', b'"symbols": {"evil": {}}')
    with pytest.raises(exceptions.ResourceIntegrityError):
        _fetch(server.url)

    from volatility3.framework import contexts

    context = contexts.Context()
    with pytest.raises(exceptions.ResourceIntegrityError):
        intermed.IntermediateSymbolTable(
            context=context,
            config_path="test.isf",
            name="isf_test",
            isf_url=server.url,
            validate=False,
        )
    assert not list(isolated_cache.glob("data_*.cache"))
    assert not list(isolated_cache.glob("*.part"))


def test_isf_is_not_parsed_when_truncated(server, isolated_cache):
    good = _isf_bytes()
    server.content = TRUNCATED
    server.declared_length = len(good)
    from volatility3.framework import contexts

    context = contexts.Context()
    with pytest.raises(exceptions.ResourceIntegrityError):
        intermed.IntermediateSymbolTable(
            context=context,
            config_path="test.isf",
            name="isf_test",
            isf_url=server.url,
            validate=False,
        )
    assert not list(isolated_cache.glob("data_*.cache"))
    assert not list(isolated_cache.glob("*.part"))


def test_truncated_compressed_isf_is_rejected(server, isolated_cache):
    import lzma

    good = lzma.compress(_isf_bytes())
    server.content = good[: len(good) // 2]
    server.declared_length = len(good)
    with pytest.raises(exceptions.ResourceIntegrityError):
        _fetch(server.url)
    assert not list(isolated_cache.glob("data_*.cache"))


def test_truncated_compressed_content_is_rejected_when_only_detected_on_read(
    server, isolated_cache
):
    import lzma

    original = _isf_bytes() * 2000
    compressed = lzma.compress(original)
    # Enough of the stream that libmagic still recognises it as xz, but not the
    # complete stream.  The server declares the truncated length, so only
    # decompression can notice the truncation.
    server.content = compressed[: len(compressed) // 2]
    server.path = "/isf.json.xz"
    with pytest.raises(exceptions.ResourceIntegrityError):
        with resources.ResourceAccessor().open(server.url) as fp:
            fp.read()
    assert not list(isolated_cache.glob("data_*.cache"))
    assert not list(isolated_cache.glob("*.part"))


# ---------------------------------------------------------------------------
# Symbol cache: a rejected remote listing is not partially applied
# ---------------------------------------------------------------------------


def _make_cache(tmp_path, monkeypatch):
    # Do not scan the installed symbol directories during these tests
    monkeypatch.setattr(
        intermed.IntermediateSymbolTable,
        "file_symbol_url",
        classmethod(lambda cls, *args, **kwargs: iter(())),
    )
    return symbol_cache.SqliteCache(str(tmp_path / "identifier.cache"))


def test_rejected_remote_listing_does_not_add_entries(tmp_path, monkeypatch):
    private, public_pem = _ed25519_keypair()
    new_identifier = base64.b64encode(b"Linux version new").decode()
    payload = {"version": 2, "linux": {new_identifier: []}}
    serialized = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    signed = dict(payload)
    signed["signature"] = {
        "algorithm": "ed25519",
        # Signature over different content: the listing must be rejected
        "signature": base64.b64encode(private.sign(serialized + b"x")).decode(),
    }
    listing = tmp_path / "signed.json"
    listing.write_text(json.dumps(signed))

    cache = _make_cache(tmp_path, monkeypatch)
    monkeypatch.setattr(constants, "OFFLINE", False)
    monkeypatch.setattr(constants, "REMOTE_ISF_URL", listing.as_uri())
    monkeypatch.setattr(constants, "REMOTE_ISF_PUBLIC_KEY", public_pem.decode())
    try:
        cache.update()
    finally:
        monkeypatch.setattr(constants, "REMOTE_ISF_PUBLIC_KEY", None)

    # The rejected listing was not partially applied
    assert cache.find_location(b"Linux version new", "linux") is None


def test_signed_remote_listing_is_applied(tmp_path, monkeypatch):
    private, public_pem = _ed25519_keypair()
    identifier = base64.b64encode(b"Linux version test").decode()
    mirror = tmp_path / "mirror.json"
    mirror.write_bytes(PAYLOAD)
    payload = {"version": 2, "linux": {identifier: [mirror.as_uri()]}}
    serialized = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    signed = dict(payload)
    signed["signature"] = {
        "algorithm": "ed25519",
        "signature": base64.b64encode(private.sign(serialized)).decode(),
    }
    listing = tmp_path / "signed.json"
    listing.write_text(json.dumps(signed))

    cache = _make_cache(tmp_path, monkeypatch)
    monkeypatch.setattr(constants, "OFFLINE", False)
    monkeypatch.setattr(constants, "REMOTE_ISF_URL", listing.as_uri())
    monkeypatch.setattr(constants, "REMOTE_ISF_PUBLIC_KEY", public_pem.decode())
    try:
        cache.update()
    finally:
        monkeypatch.setattr(constants, "REMOTE_ISF_PUBLIC_KEY", None)

    assert cache.find_location(b"Linux version test", "linux") == mirror.as_uri()


def test_remote_listing_digest_conflict_does_not_replace_identifier(
    tmp_path, monkeypatch
):
    identifier = base64.b64encode(b"Linux version test").decode()
    mirror = tmp_path / "mirror.json"
    mirror.write_bytes(PAYLOAD)
    listing = tmp_path / "listing.json"
    url = mirror.as_uri()
    listing.write_text(
        json.dumps(
            {
                "version": 2,
                "linux": {
                    identifier: [
                        {"location": url, "sha256": _sha256(PAYLOAD)},
                        {"location": url, "sha256": _sha256(SUBSTITUTED)},
                    ]
                },
            }
        )
    )
    cache = _make_cache(tmp_path, monkeypatch)
    monkeypatch.setattr(constants, "OFFLINE", False)
    monkeypatch.setattr(constants, "REMOTE_ISF_URL", listing.as_uri())
    cache.update()
    # The second conflicting digest is rejected, so the first is never replaced
    # with the substituted content's digest.
    assert resources.get_expected_hash(url) == ("sha256", _sha256(PAYLOAD))


# ---------------------------------------------------------------------------
# PDB -> ISF conversion must not publish partial symbol files
# ---------------------------------------------------------------------------


def test_download_pdb_isf_publishes_atomically(tmp_path, monkeypatch):
    from volatility3.framework.symbols.windows import pdbutil, pdbconv

    symbol_root = tmp_path / "symbols"
    symbol_root.mkdir()
    monkeypatch.setattr(
        pdbutil, "symbols", type("S", (), {"__path__": [str(symbol_root)]})
    )

    order = []

    class FakeRetriever:
        def retreive_pdb(self, guid, file_name, progress_callback=None):
            order.append("download")
            raise exceptions.ResourceIntegrityError(
                "http://127.0.0.1:1/ntkrnlmp.pdb", "truncated"
            )

    monkeypatch.setattr(pdbconv, "PdbRetreiver", FakeRetriever)
    output = symbol_root / "windows" / "ntkrnlmp.pdb" / ("A" * 32 + "-1.json.xz")
    with contextlib.suppress(Exception):
        pdbutil.PDBUtility.download_pdb_isf(None, "A" * 32, 1, "ntkrnlmp.pdb")
    assert order == ["download"]
    assert not output.exists()
    assert not list(symbol_root.rglob("*.part"))


def test_download_pdb_isf_removes_part_on_conversion_failure(tmp_path, monkeypatch):
    from volatility3.framework.symbols.windows import pdbutil, pdbconv

    symbol_root = tmp_path / "symbols"
    symbol_root.mkdir()
    monkeypatch.setattr(
        pdbutil, "symbols", type("S", (), {"__path__": [str(symbol_root)]})
    )

    class FakeRetriever:
        def retreive_pdb(self, guid, file_name, progress_callback=None):
            # A file:// URL is treated as a temporary downloaded file
            pdb = tmp_path / "downloaded.pdb"
            pdb.write_bytes(b"not really a pdb")
            return str(pdb)

    class FakeReader:
        def __init__(self, *args, **kwargs):
            pass

        def get_json(self):
            raise exceptions.ResourceIntegrityError("file:///downloaded.pdb", "corrupt")

    monkeypatch.setattr(pdbconv, "PdbRetreiver", FakeRetriever)
    monkeypatch.setattr(pdbconv, "PdbReader", FakeReader)
    output = symbol_root / "windows" / "ntkrnlmp.pdb" / ("A" * 32 + "-1.json.xz")
    pdbutil.PDBUtility.download_pdb_isf(None, "A" * 32, 1, "ntkrnlmp.pdb")
    assert not output.exists()
    assert not list(symbol_root.rglob("*.part"))
