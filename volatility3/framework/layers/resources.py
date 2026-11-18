# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import base64
import bz2
import contextlib
import gzip
import hashlib
import http.client
import json
import logging
import lzma
import os
import re
import secrets
import ssl
import sys
import tempfile
import urllib.parse
import urllib.request
import zipfile
from typing import Any, Dict, IO, List, Mapping, Optional, Tuple
from urllib import error

from volatility3 import framework
from volatility3.framework import constants, exceptions

try:
    import magic

    HAS_MAGIC = True
except ImportError:
    HAS_MAGIC = False

try:
    # Import so that the handler is found by the framework.class_subclasses call
    from smb import SMBHandler as SMBHandler  # lgtm [py/unused-import]
except ImportError:
    # If we fail to import this, it means that SMB handling won't be available
    pass

vollog = logging.getLogger(__name__)


# TODO: Type-annotating the ResourceAccessor.open method is difficult because HTTPResponse is not actually an IO[Any] type
#   fix this


### Integrity verification


SUPPORTED_HASH_ALGORITHMS = ("sha256", "sha384", "sha512")
"""Hash algorithms that are considered strong enough to verify downloaded content"""

DEFAULT_HASH_ALGORITHM = "sha256"
"""Algorithm assumed when an expected digest does not name one"""

_HASH_DIGEST_LENGTHS = {
    "sha256": 64,
    "sha384": 96,
    "sha512": 128,
}

_DECOMPRESSION_ERRORS = (EOFError, OSError, lzma.LZMAError)
"""Errors raised when a compressed stream ends before its end-of-stream marker"""


def normalize_expected_hash(expected_hash: Any) -> Optional[Tuple[str, str]]:
    """Normalizes the many ways an expected digest may be provided.

    Accepted forms are:
      * ``None`` (no expectation)
      * a hex digest string, which is assumed to be sha256 unless it carries an
        ``algorithm:`` prefix (for example ``sha256:abc...``)
      * a mapping of algorithm to hex digest (for example ``{"sha512": "abc"}``)
        or ``{"algorithm": "sha256", "digest": "abc"}``
      * a ``(algorithm, digest)`` pair

    Returns:
        A ``(algorithm, lowercase hex digest)`` tuple or None

    Raises:
        TypeError: if the value is not one of the accepted forms
        ValueError: if the algorithm is unsupported or the digest is malformed
    """
    if expected_hash is None:
        return None
    algorithm = None
    digest = None
    if isinstance(expected_hash, str):
        text = expected_hash.strip()
        if not text:
            return None
        if ":" in text:
            algorithm, _, digest = text.partition(":")
        else:
            algorithm, digest = DEFAULT_HASH_ALGORITHM, text
    elif isinstance(expected_hash, Mapping):
        if "digest" in expected_hash or "hash" in expected_hash:
            digest = expected_hash.get("digest", expected_hash.get("hash"))
            algorithm = expected_hash.get(
                "algorithm", expected_hash.get("algo", DEFAULT_HASH_ALGORITHM)
            )
        else:
            supported = [
                (algo, value)
                for algo, value in expected_hash.items()
                if str(algo).lower() in SUPPORTED_HASH_ALGORITHMS
            ]
            if not supported:
                raise ValueError(
                    f"No supported hash algorithm in expected digest mapping: {expected_hash}"
                )
            algorithm, digest = supported[0]
    elif isinstance(expected_hash, (tuple, list)) and len(expected_hash) == 2:
        algorithm, digest = expected_hash
    else:
        raise TypeError(
            f"Expected digest must be a string, mapping or pair, not {type(expected_hash).__name__}"
        )

    algorithm = str(algorithm).strip().lower()
    if algorithm not in SUPPORTED_HASH_ALGORITHMS:
        raise ValueError(
            f"Unsupported hash algorithm {algorithm!r}; supported algorithms are {', '.join(SUPPORTED_HASH_ALGORITHMS)}"
        )
    if not isinstance(digest, str):
        raise ValueError(f"Digest for {algorithm} must be a hex string")
    digest = digest.strip().lower()
    if not re.fullmatch(f"[0-9a-f]{{{_HASH_DIGEST_LENGTHS[algorithm]}}}", digest):
        raise ValueError(f"Malformed {algorithm} digest: {digest!r}")
    return algorithm, digest


# Expected digests for content that is fetched from a remote source.  They are
# keyed by URL so that any code that opens the URL (a remote ISF, a listing, a
# PDB, ...) automatically verifies the content against the expectation that was
# registered when the source was trusted (for example when a signed remote
# identifier listing was read).
_expected_hashes: Dict[str, Tuple[str, str]] = {}
_expectations_loaded_from: Optional[str] = None


def _expectations_path() -> str:
    return os.path.join(constants.CACHE_PATH, constants.REMOTE_INTEGRITY_FILENAME)


def reset_expectations() -> None:
    """Forgets the in-memory expectations so they are reloaded on next use.

    This is required when the cache path changes at runtime (for example via
    ``--cache-path``), because the expectations live next to the cache.
    """
    global _expectations_loaded_from
    _expected_hashes.clear()
    _signature_expectations.clear()
    _pinned_hashes.clear()
    _trusted_sources.clear()
    _expectations_loaded_from = None


def _load_expectations() -> None:
    global _expectations_loaded_from
    path = _expectations_path()
    if _expectations_loaded_from == path:
        return
    reset_expectations()
    _expectations_loaded_from = path
    if not os.path.exists(path):
        return
    try:
        with open(path, encoding="utf-8") as fp:
            data = json.load(fp)
    except (OSError, ValueError) as excp:
        vollog.warning(f"Unable to read remote integrity expectations: {excp}")
        return
    for url, entry in data.get("hashes", {}).items():
        try:
            normalized = normalize_expected_hash(entry)
        except (TypeError, ValueError) as excp:
            vollog.warning(f"Discarding malformed expected digest for {url}: {excp}")
            continue
        if normalized is not None:
            _expected_hashes[url] = normalized
    for url, entry in data.get("signatures", {}).items():
        try:
            signature = base64.b64decode(entry["signature"], validate=True)
        except (KeyError, TypeError, ValueError):
            vollog.warning(f"Discarding malformed expected signature for {url}")
            continue
        public_key = entry.get("public_key")
        if not public_key:
            # A signature with no trusted key cannot be verified, so it must not
            # be retained (and must certainly not soften verification).
            vollog.warning(f"Discarding unverifiable expected signature for {url}")
            continue
        _signature_expectations[url] = (
            signature,
            public_key,
            entry.get("algorithm", "ed25519"),
        )
    for url, entry in data.get("pinned", {}).items():
        try:
            normalized = normalize_expected_hash(entry)
        except (TypeError, ValueError) as excp:
            vollog.warning(f"Discarding malformed pinned digest for {url}: {excp}")
            continue
        if normalized is not None:
            _pinned_hashes[url] = normalized
    _trusted_sources.update(data.get("trusted_sources", []))


_deferred_saves = 0


@contextlib.contextmanager
def deferred_expectation_saves():
    """Batches expectation persistence while many entries are registered.

    While the context is active the expectations are kept in memory and written
    once on exit, which avoids a file rewrite per listing entry.
    """
    global _deferred_saves
    _deferred_saves += 1
    try:
        yield
    finally:
        _deferred_saves -= 1
        if _deferred_saves == 0:
            _save_expectations()


def _save_expectations() -> None:
    if _deferred_saves:
        return
    data = {
        "hashes": {
            url: f"{algorithm}:{digest}"
            for url, (algorithm, digest) in _expected_hashes.items()
        },
        "signatures": {
            url: {
                "signature": base64.b64encode(signature).decode("ascii"),
                "algorithm": algorithm,
                # The key is the one supplied by the registering caller (never
                # one read out of a downloaded document), so it is safe to keep.
                "public_key": public_key.decode("ascii")
                if isinstance(public_key, bytes)
                else public_key,
            }
            for url, (
                signature,
                public_key,
                algorithm,
            ) in _signature_expectations.items()
        },
        "pinned": {
            url: f"{algorithm}:{digest}"
            for url, (algorithm, digest) in _pinned_hashes.items()
        },
        "trusted_sources": sorted(_trusted_sources),
    }
    path = _expectations_path()
    empty = not any(
        [
            _expected_hashes,
            _signature_expectations,
            _pinned_hashes,
            _trusted_sources,
        ]
    )
    try:
        if empty:
            # Nothing is expected any more: leave no file behind
            with contextlib.suppress(FileNotFoundError):
                os.remove(path)
            return
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp_path = path + f".{os.getpid()}.part"
        with open(tmp_path, "w", encoding="utf-8") as fp:
            json.dump(data, fp)
        os.replace(tmp_path, path)
    except OSError as excp:
        vollog.warning(f"Unable to record remote integrity expectations: {excp}")


def register_expected_hash(
    url: str, expected_hash: Any, algorithm: Optional[str] = None
) -> Optional[Tuple[str, str]]:
    """Records the digest that ``url`` must have when it is opened.

    Args:
        url: The URL the expectation applies to
        expected_hash: The digest in any form accepted by
            :func:`normalize_expected_hash`, or just the hex digest when
            ``algorithm`` is provided
        algorithm: Optional algorithm name to accompany a bare digest

    Returns:
        The normalized ``(algorithm, digest)`` pair, or None if no expectation
        should be recorded
    """
    _load_expectations()
    if expected_hash is None:
        return None
    if (
        algorithm is not None
        and isinstance(expected_hash, str)
        and ":" not in expected_hash
    ):
        normalized = normalize_expected_hash(f"{algorithm}:{expected_hash}")
    else:
        normalized = normalize_expected_hash(expected_hash)
    if normalized is None:
        return None
    previous = _expected_hashes.get(url)
    if previous is not None and previous != normalized:
        vollog.warning(
            f"Expected digest for {url} changed from {previous[0]}:{previous[1]} to {normalized[0]}:{normalized[1]}"
        )
        raise exceptions.ResourceIntegrityError(
            url,
            "conflicting expected digests were registered for this location "
            f"({previous[0]}:{previous[1]} vs {normalized[0]}:{normalized[1]})",
        )
    if previous != normalized:
        _expected_hashes[url] = normalized
        # An explicit digest supersedes any trust-on-first-use pin
        _pinned_hashes.pop(url, None)
        _save_expectations()
    return normalized


def get_expected_hash(url: str) -> Optional[Tuple[str, str]]:
    """Returns the registered ``(algorithm, digest)`` expectation for a URL."""
    _load_expectations()
    return _expected_hashes.get(url)


def clear_expected_hashes() -> None:
    """Forgets every registered expected digest."""
    _load_expectations()
    _expected_hashes.clear()
    _save_expectations()


def hash_file(path: str, algorithm: str = DEFAULT_HASH_ALGORITHM) -> str:
    """Returns the hex digest of the file at ``path``."""
    algorithm = algorithm.lower()
    if algorithm not in SUPPORTED_HASH_ALGORITHMS:
        raise ValueError(f"Unsupported hash algorithm {algorithm!r}")
    hasher = hashlib.new(algorithm)
    with open(path, "rb") as fp:
        for block in iter(lambda: fp.read(1024 * 1024), b""):
            hasher.update(block)
    return hasher.hexdigest()


# Detached signatures that downloaded content must satisfy.  Keyed by URL, the
# value holds the signature, the trusted public key and the signature
# algorithm.  Keys always come from the caller's trust configuration, never
# from the document being verified.
_signature_expectations: Dict[str, Tuple[bytes, Any, str]] = {}


def register_expected_signature(
    url: str,
    signature: bytes,
    public_key: Any,
    algorithm: str = "ed25519",
) -> None:
    """Records a detached signature that ``url`` must satisfy when opened.

    Args:
        url: The URL the expectation applies to
        signature: The raw detached signature over the whole resource
        public_key: PEM encoded public key considered trusted for this URL
        algorithm: ``ed25519``, ``rsa-pss-sha256`` or ``ecdsa-p256-sha256``
    """
    if not signature:
        raise ValueError("A signature is required for a signature expectation")
    if public_key is None:
        raise ValueError("A trusted public key is required for a signature expectation")
    _load_expectations()
    if url in _signature_expectations:
        previous = _signature_expectations[url]
        if previous[0] != bytes(signature) or previous[2] != algorithm:
            raise exceptions.ResourceIntegrityError(
                url, "conflicting expected signatures were registered for this location"
            )
        if public_key is not None and previous[1] not in (None, public_key):
            raise exceptions.ResourceIntegrityError(
                url, "conflicting trusted keys were registered for this location"
            )
        if previous[1] is None:
            # A key supplied by configuration upgrades a signature-only entry
            _signature_expectations[url] = (bytes(signature), public_key, algorithm)
            _save_expectations()
        return
    _signature_expectations[url] = (bytes(signature), public_key, algorithm)
    _save_expectations()


def get_expected_signature(url: str) -> Optional[Tuple[bytes, Any, str]]:
    """Returns the registered signature expectation for a URL."""
    _load_expectations()
    return _signature_expectations.get(url)


def clear_expected_signatures() -> None:
    """Forgets every registered signature expectation."""
    _load_expectations()
    _signature_expectations.clear()
    _save_expectations()


# Digests pinned for content whose source was authenticated once (verified TLS
# to a configured mirror, or a signed listing) without carrying an explicit
# digest.  They provide trust-on-first-use: the first authenticated retrieval
# records the digest, and every later retrieval of the same URL must match it,
# so content substituted on the same URL is rejected.
_pinned_hashes: Dict[str, Tuple[str, str]] = {}
_trusted_sources: set = set()


def register_trusted_source(url: str) -> None:
    """Marks a URL whose provenance was authenticated (verified TLS to a
    configured mirror, or a signed listing).

    The first successful retrieval from a trusted source records (pins) its
    digest so later content substituted on the same URL is rejected; without
    this, an authenticated source with no per-file digest would still allow
    content that changes between runs.
    """
    _load_expectations()
    if url not in _trusted_sources:
        _trusted_sources.add(url)
        _save_expectations()


def is_trusted_source(url: str) -> bool:
    """Returns whether a URL was registered as an authenticated source."""
    _load_expectations()
    return url in _trusted_sources


def get_pinned_hash(url: str) -> Optional[Tuple[str, str]]:
    """Returns the pinned ``(algorithm, digest)`` for a URL, if any."""
    _load_expectations()
    return _pinned_hashes.get(url)


def pin_content_hash(
    url: str, path: str, algorithm: str = DEFAULT_HASH_ALGORITHM
) -> Tuple[str, str]:
    """Records the digest of verified content so later retrievals must match."""
    _load_expectations()
    algorithm = algorithm.lower()
    normalized = (
        algorithm,
        normalize_expected_hash(f"{algorithm}:{hash_file(path, algorithm)}")[1],
    )
    previous = _pinned_hashes.get(url)
    if previous is not None:
        if previous[0] != normalized[0]:
            # Already pinned with another strong algorithm; keep the existing
            # pin rather than mixing algorithms for the same location.
            return previous
        if previous[1] != normalized[1]:
            raise exceptions.ResourceIntegrityError(
                url,
                "previously pinned content digest does not match the newly retrieved content "
                f"({previous[0]}:{previous[1]} vs {normalized[0]}:{normalized[1]})",
            )
        return previous
    _pinned_hashes[url] = normalized
    _save_expectations()
    return normalized


def clear_pinned_hashes() -> None:
    """Forgets every pinned digest and trusted source."""
    _load_expectations()
    _pinned_hashes.clear()
    _trusted_sources.clear()
    _save_expectations()


def verify_downloaded_signature(
    content: bytes,
    signature: bytes,
    public_key: Any,
    algorithm: str = "ed25519",
    url: str = "<signature>",
) -> None:
    """Verifies a detached signature over downloaded content.

    Verification is performed against a caller-supplied public key (never a key
    taken from the same document as the signature), so that content can only be
    accepted when the key owner signed it.

    Args:
        content: The bytes that were downloaded
        signature: The raw detached signature
        public_key: PEM encoded public key (bytes or str)
        algorithm: ``ed25519``, ``rsa-pss-sha256`` or ``ecdsa-p256-sha256``
        url: The URL the signature applies to (reported in errors)

    Raises:
        ResourceIntegrityError: if the signature does not verify or signature
            verification is unavailable
    """
    algorithm = (algorithm or "ed25519").lower()
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as excp:
        raise exceptions.ResourceIntegrityError(
            url, "signature verification requires the cryptography module"
        ) from excp

    if isinstance(public_key, str):
        public_key = public_key.encode("utf-8")
    try:
        key = serialization.load_pem_public_key(bytes(public_key))
    except Exception as excp:
        raise exceptions.ResourceIntegrityError(
            url, f"unable to load verification public key: {excp}"
        ) from excp

    try:
        if algorithm == "ed25519":
            if not isinstance(key, Ed25519PublicKey):
                raise TypeError("key is not an Ed25519 public key")
            key.verify(signature, content)
        elif algorithm == "rsa-pss-sha256":
            if not isinstance(key, rsa.RSAPublicKey):
                raise TypeError("key is not an RSA public key")
            key.verify(
                signature,
                content,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
        elif algorithm == "ecdsa-p256-sha256":
            if not isinstance(key, ec.EllipticCurvePublicKey):
                raise TypeError("key is not an EC public key")
            key.verify(signature, content, ec.ECDSA(hashes.SHA256()))
        else:
            raise exceptions.ResourceIntegrityError(
                url, f"unsupported signature algorithm {algorithm!r}"
            )
    except InvalidSignature as excp:
        raise exceptions.ResourceIntegrityError(
            url, "detached signature does not match the downloaded content"
        ) from excp
    except TypeError as excp:
        raise exceptions.ResourceIntegrityError(
            url, f"signature verification failed: {excp}"
        ) from excp


def _is_certificate_error(reason: Any) -> bool:
    """Determines whether a urllib failure was caused by a certificate
    problem."""
    if isinstance(reason, ssl.SSLCertVerificationError):
        return True
    if isinstance(reason, ssl.CertificateError):
        return True
    if isinstance(reason, ssl.SSLError):
        # Older Pythons raised a plain SSLError with this reason instead of
        # SSLCertVerificationError (see https://github.com/volatilityfoundation/volatility3/pull/171)
        return "CERTIFICATE_VERIFY_FAILED" in str(reason)
    return False


def cascadeCloseFile(new_fp: IO[bytes], original_fp: IO[bytes]) -> IO[bytes]:
    """Really horrible solution for ensuring files aren't left open

    Args:
        new_fp: The file pointer constructed based on the original file pointer
        original_fp: The original file pointer that should be closed when the new file pointer is closed, but isn't
    """

    def close():
        original_fp.close()
        return new_fp.__class__.close(new_fp)

    new_fp.close = close
    return new_fp


class IntegrityCheckedFile:
    """Wraps a file so that late corruption is reported as an integrity error.

    Decompression is lazy, so a truncated or corrupt compressed stream is only
    discovered while reading.  This wrapper converts those errors into
    :class:`~volatility3.framework.exceptions.ResourceIntegrityError` and drops
    the cache entry, so a half file is never reused.
    """

    def __init__(self, fp: Any, url: str, cache_path: Optional[str] = None):
        self._fp = fp
        self._url = url
        self._cache_path = cache_path

    def _guard(self, excp: Exception) -> exceptions.ResourceIntegrityError:
        if self._cache_path is not None:
            with contextlib.suppress(OSError):
                os.remove(self._cache_path)
        return exceptions.ResourceIntegrityError(
            self._url, f"content is truncated or corrupt: {excp}"
        )

    def read(self, *args, **kwargs):
        try:
            return self._fp.read(*args, **kwargs)
        except _DECOMPRESSION_ERRORS as excp:
            raise self._guard(excp) from excp

    def readline(self, *args, **kwargs):
        try:
            return self._fp.readline(*args, **kwargs)
        except _DECOMPRESSION_ERRORS as excp:
            raise self._guard(excp) from excp

    def readlines(self, *args, **kwargs):
        try:
            return self._fp.readlines(*args, **kwargs)
        except _DECOMPRESSION_ERRORS as excp:
            raise self._guard(excp) from excp

    def __getattr__(self, name: str) -> Any:
        return getattr(self._fp, name)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self._fp.close()
        return False

    def __iter__(self):
        # Match file iteration semantics (yield lines) while keeping the guard
        while True:
            line = self.readline()
            if not line:
                return
            yield line

    def close(self):
        self._fp.close()


class ResourceAccessor:
    """Object for opening URLs as files (downloading locally first if
    necessary)

    Downloads are only returned once their integrity has been established:

    * TLS certificates are always verified.  A certificate failure is fatal for
      that URL (there is no unverified retry).
    * If an expected digest was registered (via
      :func:`register_expected_hash`) or passed to :meth:`open`, the content
      must match it.  Caches are verified too, so a cached file that no longer
      matches the expected content is discarded rather than used.
    * Incomplete downloads never reach the caller and never replace or create
      the cache entry.

    The accessor is also the place where a custom ``ssl.SSLContext`` (for
    example one trusting a private mirror's CA) can be supplied; that context is
    still used with certificate and hostname verification enabled.
    """

    list_handlers = True

    def __init__(
        self,
        progress_callback: Optional[constants.ProgressCallback] = None,
        context: Optional[ssl.SSLContext] = None,
        enable_cache: bool = True,
        expected_hash: Any = None,
    ) -> None:
        """Creates a resource accessor.

        Args:
            progress_callback: Called with progress updates while downloading
            context: An ssl.SSLContext to use for TLS connections (not a
                volatility context)
            enable_cache: Whether downloadable content should be cached locally
            expected_hash: Optional digest every opened resource must match
        """
        self._progress_callback = progress_callback
        self._context = context
        self._handlers = list(framework.class_subclasses(urllib.request.BaseHandler))
        self._enable_cache = enable_cache
        self._expected_hash = normalize_expected_hash(expected_hash)
        if self.list_handlers:
            vollog.log(
                constants.LOGLEVEL_VVV,
                f"Available URL handlers: {', '.join([x.__name__ for x in self._handlers])}",
            )
            self.__class__.list_handlers = False

    def uses_cache(self, url: str) -> bool:
        """Determines whether a URLs contents should be cached"""
        parsed_url = urllib.parse.urlparse(url)

        return (
            self._enable_cache and parsed_url.scheme not in self._non_cached_schemes()
        )

    @staticmethod
    def _non_cached_schemes() -> List[str]:
        """Returns the list of schemes not to be cached"""
        result = ["file"]
        for clazz in framework.class_subclasses(VolatilityHandler):
            result += clazz.non_cached_schemes()
        return result

    @staticmethod
    def _cache_filename(url: str) -> str:
        """Returns the cache path used for a URL."""
        return os.path.join(
            constants.CACHE_PATH,
            "data_"
            + hashlib.sha512(bytes(url, "raw_unicode_escape")).hexdigest()
            + ".cache",
        )

    def _resolve_expected_hash(
        self, url: str, expected_hash: Any
    ) -> Optional[Tuple[str, str]]:
        if expected_hash is not None:
            return normalize_expected_hash(expected_hash)
        if self._expected_hash is not None:
            return self._expected_hash
        expected = get_expected_hash(url)
        if expected is None:
            # Content whose source was authenticated once must not change later
            expected = get_pinned_hash(url)
        return expected

    def _record_verified(self, url: str, path: Optional[str]) -> None:
        """Pins the digest of authenticated content for future retrievals."""
        if path is not None and is_trusted_source(url):
            pin_content_hash(url, path)

    @staticmethod
    def _verify_signature_expectations(
        url: str, fp: Optional[Any], path: Optional[str]
    ) -> None:
        """Verifies any registered detached signature for ``url``.

        Content that has a signature expectation but cannot be verified (for
        example because the signing module is unavailable) is rejected rather
        than accepted unverified.
        """
        expectation = get_expected_signature(url)
        if expectation is None:
            return
        signature, public_key, algorithm = expectation
        if path is not None:
            with open(path, "rb") as signed_fp:
                content = signed_fp.read()
        else:
            fp.seek(0)
            content = fp.read()
            fp.seek(0)
        verify_downloaded_signature(content, signature, public_key, algorithm, url=url)

    def _open_url(self, url: str) -> Any:
        """Opens a URL with mandatory certificate verification."""
        urllib.request.install_opener(urllib.request.build_opener(*self._handlers))
        context = self._context
        parsed = urllib.parse.urlparse(url)
        if constants.OFFLINE and parsed.scheme in ("http", "https"):
            # Enforced here as well as by the OfflineHandler, so that offline
            # mode never depends on handler ordering.
            vollog.info(f"Not accessing {url} in offline mode")
            raise exceptions.OfflineException(url)
        if context is None and parsed.scheme in ("http", "https"):
            # An explicit default context documents (and enforces) that
            # verification is on; it also honours SSL_CERT_FILE/DIR.
            context = ssl.create_default_context()
        try:
            return urllib.request.urlopen(url, context=context)
        except error.URLError as excp:
            reason = excp.args[0] if excp.args else excp
            if _is_certificate_error(reason):
                raise exceptions.ResourceIntegrityError(
                    url, f"TLS certificate verification failed: {reason}"
                ) from excp
            raise
        except ssl.SSLCertVerificationError as excp:
            raise exceptions.ResourceIntegrityError(
                url, f"TLS certificate verification failed: {excp}"
            ) from excp
        except ValueError as excp:
            # Reraise errors such as proxy auth errors as offline exception errors
            # Example Proxy auth error - ValueError: AbstractDigestAuthHandler does not support the following scheme: 'Negotiate'
            vollog.info(f"Cannot access {url} due to {excp} - Setting OFFLINE")
            constants.OFFLINE = True
            raise exceptions.OfflineException(url)
        except exceptions.OfflineException:
            vollog.info(f"Not accessing {url} in offline mode")
            raise

    @staticmethod
    def _content_length(fp: Any) -> Optional[int]:
        try:
            value = int(fp.info().get("Content-Length", -1))
        except (AttributeError, TypeError, ValueError):
            return None
        return value if value >= 0 else None

    @staticmethod
    def _destination_part_name(destination: Optional[str]) -> Tuple[Any, Optional[str]]:
        """Creates a unique part file next to the destination (or an anonymous
        temporary file when there is no destination)."""
        if destination is None:
            return tempfile.TemporaryFile(), None
        directory = os.path.dirname(destination) or "."
        os.makedirs(directory, exist_ok=True)
        part = os.path.join(
            directory,
            os.path.basename(destination)
            + f".{os.getpid()}.{secrets.token_hex(8)}.part",
        )
        return open(part, "xb"), part

    def _download(
        self,
        url: str,
        expected: Optional[Tuple[str, str]],
        destination: Optional[str],
    ) -> Any:
        """Downloads ``url`` to a temporary file, verifies it and publishes it.

        Returns an open, read-only file object.  The final cache path (if any)
        only appears once the complete, verified content is in place, so an
        interrupted or rejected download never leaves a reusable half file.
        """
        fp = self._open_url(url)
        part_path = None
        part_fp = None
        try:
            with contextlib.closing(fp):
                parsed = urllib.parse.urlparse(url)
                final = fp.geturl() if hasattr(fp, "geturl") else url
                if parsed.scheme == "https" and urllib.parse.urlparse(
                    final
                ).scheme not in ("https",):
                    raise exceptions.ResourceIntegrityError(
                        url,
                        f"refusing downgrade from https to {urllib.parse.urlparse(final).scheme or 'an unknown scheme'}",
                    )
                content_length = self._content_length(fp)
                part_fp, part_path = self._destination_part_name(destination)
                hasher = hashlib.new(expected[0]) if expected is not None else None
                block_size = 1028 * 8
                count = 0
                try:
                    block = fp.read(block_size)
                    while block:
                        count += len(block)
                        if self._progress_callback:
                            self._progress_callback(
                                count * 100 / max(count, content_length or count),
                                f"Reading file {url}",
                            )
                        if hasher is not None:
                            hasher.update(block)
                        part_fp.write(block)
                        block = fp.read(block_size)
                except http.client.IncompleteRead as excp:
                    raise exceptions.ResourceIntegrityError(
                        url, f"download was truncated: {excp}"
                    ) from excp
                except (ConnectionResetError, ConnectionAbortedError) as excp:
                    raise exceptions.ResourceIntegrityError(
                        url, f"download was truncated: {excp}"
                    ) from excp

                if content_length is not None and count != content_length:
                    raise exceptions.ResourceIntegrityError(
                        url,
                        f"download was truncated (received {count} of {content_length} bytes)",
                    )
                if part_path is not None:
                    part_fp.flush()
                    os.fsync(part_fp.fileno())
                    part_fp.close()
                    part_fp = None

                if expected is not None:
                    digest = (
                        hasher.hexdigest()
                        if part_path is None
                        else hash_file(part_path, expected[0])
                    )
                    if digest != expected[1]:
                        raise exceptions.ResourceIntegrityError(
                            url,
                            f"content did not match the expected {expected[0]} digest "
                            f"({digest} != {expected[1]})",
                        )

                self._verify_signature_expectations(url, part_fp, part_path)
                if part_path is not None:
                    self._record_verified(url, part_path)

                if destination is None:
                    # Anonymous temporary file: rewind and hand it back.  It is
                    # removed by the OS when the caller closes it.
                    if part_path is not None:
                        raise RuntimeError(
                            "unexpected named part file for anonymous download"
                        )
                    part_fp.seek(0)
                    result, part_fp = part_fp, None
                    return result
                os.replace(part_path, destination)
                part_path = None
                return open(destination, "rb")
        finally:
            if part_fp is not None:
                with contextlib.suppress(Exception):
                    part_fp.close()
            if part_path is not None and os.path.exists(part_path):
                with contextlib.suppress(OSError):
                    os.remove(part_path)

    def _decompress(self, curfile: Any, url: str, mode: str) -> Any:
        """Applies content-based or extension-based decompression."""
        try:
            return self._apply_decompression(curfile, url, mode)
        except _DECOMPRESSION_ERRORS as excp:
            # A compressed stream that cannot be read to the end was not the
            # complete content that was published.  Report it as an integrity
            # failure so a truncated archive is never handed to a parser.
            raise exceptions.ResourceIntegrityError(
                url, f"compressed content is truncated or corrupt: {excp}"
            ) from excp

    def _apply_decompression(self, curfile: Any, url: str, mode: str) -> Any:
        """Determines whether the file is a particular type of file, and if so,
        opens it as such."""
        IMPORTED_MAGIC = False
        if HAS_MAGIC:
            stop = False
            while not stop:
                detected = None
                with contextlib.suppress(AttributeError, IOError):
                    # Detect the content
                    detected = magic.detect_from_fobj(curfile)
                    IMPORTED_MAGIC = True
                    # This is because python-magic and file provide a magic module
                    # Only file's python has magic.detect_from_fobj

                if detected:
                    if detected.mime_type == "application/x-xz":
                        curfile = cascadeCloseFile(
                            lzma.LZMAFile(curfile, mode), curfile
                        )
                    elif detected.mime_type == "application/x-bzip2":
                        curfile = cascadeCloseFile(bz2.BZ2File(curfile, mode), curfile)
                    elif detected.mime_type == "application/x-gzip":
                        curfile = cascadeCloseFile(
                            gzip.GzipFile(fileobj=curfile, mode=mode), curfile
                        )
                    if detected.mime_type in [
                        "application/x-xz",
                        "application/x-bzip2",
                        "application/x-gzip",
                    ]:
                        # Read and rewind to ensure we're inside any compressed file layers
                        curfile.read(1)
                        curfile.seek(0)
                    else:
                        stop = True
                else:
                    stop = True

        if not IMPORTED_MAGIC:
            # Somewhat of a hack, but prevents a hard dependency on the magic module
            parsed_url = urllib.parse.urlparse(url)
            url_path = parsed_url.path
            stop = False
            while not stop:
                url_path_split = url_path.split(".")
                url_path_list, extension = url_path_split[:-1], url_path_split[-1]
                url_path = ".".join(url_path_list)
                if extension == "xz":
                    curfile = cascadeCloseFile(lzma.LZMAFile(curfile, mode), curfile)
                elif extension == "bz2":
                    curfile = cascadeCloseFile(bz2.BZ2File(curfile, mode), curfile)
                elif extension == "gz":
                    curfile = cascadeCloseFile(
                        gzip.GzipFile(fileobj=curfile, mode=mode), curfile
                    )
                else:
                    stop = True

        return curfile

    def _open_cached(self, cache_filename: str, url: str, mode: str) -> Any:
        """Opens a cached file and decompresses it, closing it on failure."""
        fp = open(cache_filename, "rb")
        try:
            decompressed = self._decompress(fp, url, mode)
        except Exception:
            fp.close()
            raise
        return self._wrap(decompressed, url, cache_filename)

    def open(self, url: str, mode: str = "rb", expected_hash: Any = None) -> Any:
        """Returns a file-like object for a particular URL opened in mode.

        If the file is remote, it will be downloaded and locally cached.  The
        returned object is only produced after the content has passed the
        integrity checks described on the class.

        Args:
            url: The URL to open
            mode: The mode in which to open the resource ("rb" by default)
            expected_hash: Overrides any registered expectation for this URL.
                See :func:`normalize_expected_hash` for accepted forms.
        """
        # Python bug 46654
        if sys.platform == "win32":
            # We only need to worry about UNC paths on windows, on linux they'd be smb:// and need pysmb or similar
            parsed_url = urllib.parse.urlparse(url, scheme="file")
            # Only worry about file scheme URLs, make sure that there's either a host or
            # the unparsing left an extra slash at the start (which will get lost with urlunparse)
            if parsed_url.scheme == "file" and (
                parsed_url.netloc or parsed_url.path.startswith("//")
            ):
                # Change the netloc to '/' and then prepend the netloc to the path
                # Urlunparse will remove extra initial slashes from path, hence setting netloc
                new_url = urllib.parse.urlunparse(
                    (
                        parsed_url.scheme,
                        "/",
                        "/" + parsed_url.netloc + parsed_url.path,
                        parsed_url.params,
                        parsed_url.query,
                        parsed_url.fragment,
                    )
                )
                vollog.log(
                    constants.LOGLEVEL_VVVV,
                    f"UNC path detected, converted path {url} to {new_url}",
                )
                url = new_url

        expected = self._resolve_expected_hash(url, expected_hash)
        cacheable = self.uses_cache(url)
        cache_filename = self._cache_filename(url) if cacheable else None

        # A cache hit is only usable if it still satisfies the expectation.  A
        # mismatching cached file is a conflict: it is removed and the open
        # fails, so nothing is ever parsed from content that disagrees with what
        # the source is known to publish.
        if cache_filename is not None and os.path.exists(cache_filename):
            if self._cache_is_usable(cache_filename, expected, url):
                vollog.debug(f"Trying to use already cached file at: {cache_filename}")
                return self._open_cached(cache_filename, url, mode)
            if expected is not None or get_expected_signature(url) is not None:
                vollog.warning(
                    f"Cached content for {url} conflicts with its expected "
                    "integrity data; discarding it and refusing to parse it"
                )
                self._discard(cache_filename)
                raise exceptions.ResourceIntegrityError(
                    url,
                    "cached content conflicts with the expected digest/signature",
                )
            vollog.warning(
                f"Cached content for {url} could not be verified; discarding it"
            )
            self._discard(cache_filename)

        if not cacheable:
            if expected is None and get_expected_signature(url) is None:
                curfile = self._open_url(url)
                return self._wrap(self._decompress(curfile, url, mode), url)
            # Verified non-cacheable content (for example a cloud object) is
            # staged in an anonymous temporary file, which disappears on close.
            return self._wrap(
                self._decompress(self._download(url, expected, None), url, mode), url
            )

        try:
            return self._wrap(
                self._decompress(
                    self._download(url, expected, cache_filename), url, mode
                ),
                url,
                cache_filename,
            )
        except exceptions.OfflineException:
            # An offline run can still use content that was cached and verified
            # earlier; anything else is unavailable.
            if os.path.exists(cache_filename) and self._cache_is_usable(
                cache_filename, expected, url
            ):
                vollog.info(f"Using cached copy of {url} while offline")
                return self._open_cached(cache_filename, url, mode)
            raise
        except error.URLError as excp:
            if os.path.exists(cache_filename) and self._cache_is_usable(
                cache_filename, expected, url
            ):
                vollog.warning(
                    f"Unable to retrieve {url} ({excp}); using the verified cached copy"
                )
                return self._open_cached(cache_filename, url, mode)
            raise

    @staticmethod
    def _wrap(curfile: Any, url: str, cache_path: Optional[str] = None) -> Any:
        """Wraps a returned handle so deferred corruption is reported cleanly."""
        return IntegrityCheckedFile(curfile, url, cache_path)

    def _cache_is_usable(
        self, path: str, expected: Optional[Tuple[str, str]], url: str
    ) -> bool:
        """Determines whether a cached file still satisfies its expectations."""
        if expected is not None and not self._matches(path, expected, url):
            return False
        if get_expected_signature(url) is not None:
            try:
                self._verify_signature_expectations(url, None, path)
            except (
                exceptions.ResourceIntegrityError,
                OSError,
            ) as excp:
                vollog.warning(f"Unable to verify cached signature for {url}: {excp}")
                return False
        return True

    @staticmethod
    def _matches(path: str, expected: Tuple[str, str], url: str) -> bool:
        try:
            return hash_file(path, expected[0]) == expected[1]
        except (OSError, ValueError) as excp:
            vollog.warning(f"Unable to verify cached content {path}: {excp}")
            return False

    @staticmethod
    def _discard(path: str) -> None:
        with contextlib.suppress(OSError):
            os.remove(path)


class VolatilityHandler(urllib.request.BaseHandler):
    @classmethod
    def non_cached_schemes(cls) -> List[str]:
        return []


class JarHandler(VolatilityHandler):
    """Handles the jar scheme for URIs.

    Reference used for the schema syntax:
    http://docs.netkernel.org/book/view/book:mod:reference/doc:layer1:schemes:jar

    Actual reference (found from https://www.w3.org/wiki/UriSchemes/jar) seemed not to return:
    http://developer.java.sun.com/developer/onlineTraining/protocolhandlers/
    """

    @classmethod
    def non_cached_schemes(cls) -> List[str]:
        return ["jar"]

    @staticmethod
    def default_open(req: urllib.request.Request) -> Optional[Any]:
        """Handles the request if it's the jar scheme."""
        if req.type == "jar":
            subscheme, remainder = (
                req.full_url.split(":")[1],
                ":".join(req.full_url.split(":")[2:]),
            )
            if subscheme != "file":
                vollog.log(
                    constants.LOGLEVEL_VVV, f"Unsupported jar subscheme {subscheme}"
                )
                return None

            zipsplit = remainder.split("!")
            if len(zipsplit) != 2:
                vollog.log(
                    constants.LOGLEVEL_VVV,
                    f"Path did not contain exactly one fragment indicator: {remainder}",
                )
                return None

            zippath, filepath = zipsplit
            return zipfile.ZipFile(zippath).open(filepath)
        return None


class OfflineHandler(VolatilityHandler):
    @staticmethod
    def default_open(req: urllib.request.Request) -> Optional[Any]:
        if constants.OFFLINE and req.type in ["http", "https"]:
            raise exceptions.OfflineException(req.full_url)
        return None
