# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
import base64
import datetime
import json
import logging
import os
import sqlite3
import urllib
import urllib.parse
import urllib.request
from abc import abstractmethod
from typing import Any, Dict, Generator, Iterable, List, Optional, Tuple

from volatility3 import framework, schemas
from volatility3.framework import constants, exceptions, interfaces
from volatility3.framework.configuration import requirements
from volatility3.framework.layers import resources
from volatility3.framework.symbols import intermed

vollog = logging.getLogger(__name__)

BannersType = Dict[bytes, List[str]]

SUPPORTED_HASH_KEYS = resources.SUPPORTED_HASH_ALGORITHMS


### Identifiers


class IdentifierProcessor:
    operating_system = None

    def __init__(self):
        pass

    @classmethod
    @abstractmethod
    def get_identifier(cls, json) -> Optional[bytes]:
        """Method to extract the identifier from a particular operating system's JSON

        Returns:
            identifier is valid or None if not found
        """
        raise NotImplementedError(
            "This base class has no get_identifier method defined"
        )


class WindowsIdentifier(IdentifierProcessor):
    operating_system = "windows"
    separator = "|"

    @classmethod
    def get_identifier(cls, json) -> Optional[bytes]:
        """Returns the identifier for the file if one can be found"""
        windows_metadata = json.get("metadata", {}).get("windows", {}).get("pdb", {})
        if windows_metadata:
            guid = windows_metadata.get("GUID", None)
            age = windows_metadata.get("age", None)
            database = windows_metadata.get("database", None)
            if guid and age and database:
                return cls.generate(database, guid, age)
        return None

    @classmethod
    def generate(cls, pdb_name: str, guid: str, age: int) -> bytes:
        return bytes(cls.separator.join([pdb_name, guid.upper(), str(age)]), "latin-1")


class MacIdentifier(IdentifierProcessor):
    operating_system = "mac"

    @classmethod
    def get_identifier(cls, json) -> Optional[bytes]:
        mac_banner = (
            json.get("symbols", {}).get("version", {}).get("constant_data", None)
        )
        if mac_banner:
            return base64.b64decode(mac_banner)
        return None


class LinuxIdentifier(IdentifierProcessor):
    operating_system = "linux"

    @classmethod
    def get_identifier(cls, json) -> Optional[bytes]:
        linux_banner = (
            json.get("symbols", {}).get("linux_banner", {}).get("constant_data", None)
        )
        if linux_banner:
            return base64.b64decode(linux_banner)
        return None


### CacheManagers


class CacheManagerInterface(interfaces.configuration.VersionableInterface):
    def __init__(self, filename: str):
        super().__init__()
        self._filename = filename
        self._classifiers = {}
        for subclazz in framework.class_subclasses(IdentifierProcessor):
            self._classifiers[subclazz.operating_system] = subclazz

    @abstractmethod
    def add_identifier(self, location: str, operating_system: str, identifier: str):
        """Adds an identifier to the store"""

    @abstractmethod
    def find_location(
        self, identifier: bytes, operating_system: Optional[str]
    ) -> Optional[str]:
        """Returns the location of the symbol file given the identifier

        Args:
            identifier: string that uniquely identifies a particular symbol table
            operating_system: optional string to restrict identifiers to just those for a particular operating system

        Returns:
            The location of the symbols file that matches the identifier
        """

    @abstractmethod
    def get_local_locations(self) -> Iterable[str]:
        """Returns a list of all the local locations"""

    @abstractmethod
    def update(self):
        """Locates all files under the symbol directories.  Updates the cache with additions, modifications and removals.
        This also updates remote locations based on a cache timeout.

        """

    @abstractmethod
    def get_identifier_dictionary(
        self, operating_system: Optional[str] = None, local_only: bool = False
    ) -> Dict[bytes, str]:
        """Returns a dictionary of identifiers and locations

        Args:
            operating_system: If set, limits responses to a specific operating system
            local_only: Returns only local locations

        Returns:
            A dictionary of identifiers mapped to a location
        """

    @abstractmethod
    def get_identifier(self, location: str) -> Optional[bytes]:
        """Returns an identifier based on a specific location or None"""

    @abstractmethod
    def get_identifiers(self, operating_system: Optional[str]) -> List[bytes]:
        """Returns all identifiers for a particular operating system"""

    @abstractmethod
    def get_location_statistics(
        self, location: str
    ) -> Optional[Tuple[int, int, int, int]]:
        """Returns ISF statistics based on the location

        Returns:
            A tuple of base_types, types, enums, symbols, or None is location not found
        """

    @abstractmethod
    def get_hash(self, location: str) -> Optional[str]:
        """Returns the hash of the JSON from within a location ISF"""


class SqliteCache(CacheManagerInterface):
    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    def __init__(self, filename: str):
        super().__init__(filename)
        self.cache_period = constants.SQLITE_CACHE_PERIOD
        try:
            self._database = self._connect_storage(filename)
        except sqlite3.DatabaseError:
            os.unlink(filename)
            self._database = self._connect_storage(filename)

    def _connect_storage(self, path: str) -> sqlite3.Connection:
        database = sqlite3.connect(path)
        database.row_factory = sqlite3.Row

        database.cursor().execute(
            f"CREATE TABLE IF NOT EXISTS database_info (schema_version INT DEFAULT {constants.CACHE_SQLITE_SCHEMA_VERSION})"
        )
        schema_version = (
            database.cursor()
            .execute("SELECT schema_version FROM database_info")
            .fetchone()
        )
        if not schema_version:
            database.cursor().execute(
                f"INSERT INTO database_info VALUES ({constants.CACHE_SQLITE_SCHEMA_VERSION})"
            )
        elif schema_version["schema_version"] == constants.CACHE_SQLITE_SCHEMA_VERSION:
            # All good, so pass and move on
            pass
        else:
            vollog.info(
                f"Previous cache schema version found: {schema_version['schema_version']}"
            )
            # TODO: Implement code if the schema changes
            # Current this should never happen so we start over again
            database.close()
            os.unlink(path)
            return self._connect_storage(path)
        database.cursor().execute(
            "CREATE TABLE IF NOT EXISTS cache (location TEXT UNIQUE NOT NULL, identifier TEXT, operating_system TEXT, hash TEXT,"
            "stats_base_types INT DEFAULT 0, stats_types INT DEFAULT 0, stats_enums INT DEFAULT 0, stats_symbols INT DEFAULT 0, local BOOL, cached DATETIME)"
        )
        database.commit()
        return database

    def find_location(
        self, identifier: bytes, operating_system: Optional[str]
    ) -> Optional[str]:
        """Returns the location of the symbol file given the identifier.
        If multiple locations exist for an identifier, the last found is returned

        Args:
            identifier: string that uniquely identifies a particular symbol table
            operating_system: optional string to restrict identifiers to just those for a particular operating system

        Returns:
            The location of the symbols file that matches the identifier or None
        """
        statement = "SELECT location FROM cache WHERE identifier = ?"
        parameters = (identifier,)
        if operating_system is not None:
            statement = "SELECT location FROM cache WHERE identifier = ? AND operating_system = ?"
            parameters = (identifier, operating_system)
        results = self._database.cursor().execute(statement, parameters).fetchall()
        result = None
        for row in results:
            result = row["location"]
        return result

    def get_local_locations(self) -> Generator[str, None, None]:
        result = (
            self._database.cursor()
            .execute("SELECT DISTINCT location FROM cache WHERE local = 1")
            .fetchall()
        )
        for row in result:
            yield row["location"]

    def is_url_local(self, url: str) -> bool:
        """Determines whether an url is local or not"""
        parsed = urllib.parse.urlparse(url)
        return parsed.scheme in ["file", "jar"]

    def get_identifier(self, location: str) -> Optional[bytes]:
        results = (
            self._database.cursor()
            .execute("SELECT identifier FROM cache WHERE location = ?", (location,))
            .fetchall()
        )
        for row in results:
            return row["identifier"]
        return None

    def get_location_statistics(
        self, location: str
    ) -> Optional[Tuple[int, int, int, int]]:
        results = (
            self._database.cursor()
            .execute(
                "SELECT stats_base_types, stats_types, stats_enums, stats_symbols FROM cache WHERE location = ?",
                (location,),
            )
            .fetchall()
        )
        for row in results:
            return (
                row["stats_base_types"],
                row["stats_types"],
                row["stats_enums"],
                row["stats_symbols"],
            )
        return None

    def get_hash(self, location: str) -> Optional[str]:
        results = (
            self._database.cursor()
            .execute("SELECT hash FROM cache WHERE location = ?", (location,))
            .fetchall()
        )
        for row in results:
            return row["hash"]
        return None

    def update(self, progress_callback=None):
        """Locates all files under the symbol directories.  Updates the cache with additions, modifications and removals.
        This also updates remote locations based on a cache timeout.

        """
        if progress_callback is None:

            def dummy_progress(*args, **kargs) -> None:
                return None

            progress_callback = dummy_progress

        on_disk_locations = set(
            [
                filename
                for filename in intermed.IntermediateSymbolTable.file_symbol_url("")
            ]
        )
        cached_locations = set(self.get_local_locations())

        new_locations = on_disk_locations.difference(cached_locations)
        missing_locations = cached_locations.difference(on_disk_locations)

        # Missing entries
        if missing_locations:
            self._database.cursor().execute(
                f"DELETE FROM cache WHERE location IN ({','.join(['?'] * len(missing_locations))})",
                [x for x in missing_locations],
            )
            self._database.commit()

        cache_update = set()
        files_to_timestamp = on_disk_locations.intersection(cached_locations)
        if files_to_timestamp:
            result = self._database.cursor().execute(
                "SELECT location, cached FROM cache WHERE local = 1 "
                f"AND cached < date('now', '{self.cache_period}');"
            )
            for row in result:
                location = row["location"]
                stored_timestamp = datetime.datetime.fromisoformat(row["cached"])
                timestamp = stored_timestamp  # Default to requiring update

                # See if the file is a local URL type we can handle:
                parsed = urllib.parse.urlparse(location)
                pathname = None
                if parsed.scheme == "file":
                    pathname = urllib.request.url2pathname(parsed.path)
                if parsed.scheme == "jar":
                    inner_url = urllib.parse.urlparse(parsed.path)
                    if inner_url.scheme == "file":
                        pathname = inner_url.path.split("!")[0]

                if pathname and os.path.exists(pathname):
                    timestamp = datetime.datetime.fromtimestamp(
                        os.stat(pathname).st_mtime
                    )
                else:
                    vollog.log(
                        constants.LOGLEVEL_VVVV,
                        "File location in database classed as local but not file/jar URL",
                    )

                # If we're supposed to include it, and our last check is older than (or equal to) the file timestamp
                if (
                    row["location"] in files_to_timestamp
                    and stored_timestamp < timestamp
                ):
                    cache_update.add(row["location"])

        idextractors = list(framework.class_subclasses(IdentifierProcessor))

        # New or not recently updated

        files_to_process = new_locations.union(cache_update)
        number_files_to_process = len(files_to_process)
        cursor = self._database.cursor()
        try:
            for counter, location in enumerate(files_to_process):
                # Open location
                progress_callback(
                    counter * 100 / number_files_to_process,
                    f"Updating caches for {number_files_to_process} files...",
                )
                try:
                    with resources.ResourceAccessor().open(location) as fp:
                        json_obj = json.load(fp)
                        hash = schemas.create_json_hash(json_obj)
                        identifier = None

                        # Get stats
                        stats_base_types = len(json_obj.get("base_types", {}))
                        stats_types = len(json_obj.get("user_types", {}))
                        stats_enums = len(json_obj.get("enums", {}))
                        stats_symbols = len(json_obj.get("symbols", {}))

                        operating_system = None
                        for idextractor in idextractors:
                            identifier = idextractor.get_identifier(json_obj)
                            if identifier is not None:
                                operating_system = idextractor.operating_system
                                break

                        # We don't try to validate schemas here, we do that on first use
                        # Store in database
                        cursor.execute(
                            "INSERT OR REPLACE INTO cache (location, identifier, operating_system, hash,"
                            "stats_base_types, stats_types, stats_enums, stats_symbols, "
                            "local, cached) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))",
                            (
                                location,
                                identifier,
                                operating_system,
                                hash,
                                stats_base_types,
                                stats_types,
                                stats_enums,
                                stats_symbols,
                                self.is_url_local(location),
                            ),
                        )
                        if identifier is not None:
                            vollog.log(
                                constants.LOGLEVEL_VV,
                                f"Identified {location} as {identifier}",
                            )
                        else:
                            vollog.log(
                                constants.LOGLEVEL_VVVV,
                                f"No identifier found for {location}",
                            )
                except Exception as excp:
                    vollog.log(constants.LOGLEVEL_VVVV, excp)
        finally:
            self._database.commit()

        # Remote Entries

        if not constants.OFFLINE and constants.REMOTE_ISF_URL:
            progress_callback(0, "Reading remote ISF list")
            cursor = self._database.cursor()
            cursor.execute(
                f"SELECT cached FROM cache WHERE local = 0 and cached < datetime('now', '{self.cache_period}')"
            )
            try:
                remote_identifiers = RemoteIdentifierFormat(
                    constants.REMOTE_ISF_URL,
                    trusted_key=constants.REMOTE_ISF_PUBLIC_KEY,
                )
            except exceptions.ResourceIntegrityError as excp:
                # A listing that fails verification must not be partially
                # applied.  Previously cached remote entries stay usable (their
                # content is still checked when it is opened).
                vollog.warning(
                    f"Remote ISF list rejected, keeping existing remote entries: {excp}"
                )
                return
            progress_callback(50, "Reading remote ISF list")
            # Batch the digest registrations so the expectation file is written
            # once rather than once per listing entry.
            with resources.deferred_expectation_saves():
                for operating_system in constants.OS_CATEGORIES:
                    identifiers = remote_identifiers.process(
                        {}, operating_system=operating_system
                    )
                    for identifier, location in identifiers:
                        identifier = identifier.rstrip()
                        identifier = (
                            identifier[:-1]
                            if identifier.endswith(b"\x00")
                            else identifier
                        )  # Linux banners dumped by dwarf2json end with "\x00\n". If not stripped, the banner cannot match.
                        cursor.execute(
                            "INSERT OR REPLACE INTO cache(identifier, location, operating_system, local, cached) VALUES (?, ?, ?, ?, datetime('now'))",
                            (identifier, location, operating_system, False),
                        )
            progress_callback(100, "Reading remote ISF list")
            self._database.commit()

    def get_identifier_dictionary(
        self, operating_system: Optional[str] = None, local_only: bool = False
    ) -> Dict[bytes, str]:
        output = {}
        additions = []
        statement = "SELECT location, identifier FROM cache"
        if local_only:
            additions.append("local = 1")
        if operating_system:
            additions.append(f"operating_system = '{operating_system}'")
        if additions:
            statement += f" WHERE {' AND '.join(additions)}"
        results = self._database.cursor().execute(statement)
        for row in results:
            if row["identifier"] in output and row["identifier"] and row["location"]:
                vollog.debug(
                    f"Duplicate entry for identifier {row['identifier']}: {row['location']} and {output[row['identifier']]}"
                )
            output[row["identifier"]] = row["location"]
        return output

    def get_identifiers(self, operating_system: Optional[str]) -> List[bytes]:
        if operating_system:
            results = (
                self._database.cursor()
                .execute(
                    "SELECT identifier FROM cache WHERE operating_system = ?",
                    (operating_system,),
                )
                .fetchall()
            )
        else:
            results = (
                self._database.cursor()
                .execute("SELECT identifier FROM cache")
                .fetchall()
            )
        output = []
        for row in results:
            output.append(row["identifier"])
        return output


def load_cache_manager(cache_file: Optional[str] = None) -> CacheManagerInterface:
    """Loads a cache manager based on a specific cache file"""
    if cache_file is None:
        cache_file = os.path.join(constants.CACHE_PATH, constants.IDENTIFIERS_FILENAME)
    # Different implementations of cache
    if not os.path.exists(cache_file):
        raise ValueError("Non-existent cache file provided")
    with open(cache_file, "rb") as fp:
        header = fp.read(4)
        if header not in [b"SQLi"]:
            raise ValueError("Identifier file not in recognized format")
    # Currently only one choice, so use that
    return SqliteCache(cache_file)


### Automagic


class SymbolCacheMagic(interfaces.automagic.AutomagicInterface):
    """Runs through all symbol tables and caches their identifiers"""

    priority = 0

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        identifiers_path = os.path.join(
            constants.CACHE_PATH, constants.IDENTIFIERS_FILENAME
        )
        self._cache = SqliteCache(identifiers_path)

    def __call__(self, context, config_path, configurable, progress_callback=None):
        """Runs the automagic over the configurable."""
        self._cache.update(progress_callback)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        """Returns a list of RequirementInterface objects required by this
        object."""
        return [
            requirements.VersionRequirement(
                name="SQLiteCache", component=SqliteCache, version=(1, 0, 0)
            )
        ]


class RemoteIdentifierFormat:
    """A list of remote symbol locations, together with the integrity data that
    each location must satisfy.

    Supported formats:

    * **Version 2** - the integrity-aware format::

          {
            "version": 2,
            "windows": {
              "<base64 identifier>": [
                {"location": "https://mirror/.../ntkrnlmp.json.xz",
                 "sha256": "<hex digest>"},
                {"url": "https://mirror/.../other.json.xz",
                 "hash": {"algorithm": "sha512", "digest": "<hex digest>"}}
              ]
            },
            "additional": ["https://mirror/other-listing.json"],
            "signature": {"algorithm": "ed25519", "signature": "<base64>"}
          }

      Entries may also be plain dictionaries mapping a location to its digest
      (``{"https://...": "<sha256 hex>"}``).  The optional ``signature`` is a
      detached signature over the listing (with the ``signature`` member
      removed) and is only accepted when a trusted public key has been
      configured via :data:`constants.REMOTE_ISF_PUBLIC_KEY`.

    * **Version 1** - the legacy ``{os: {b64 identifier: [url, ...]}}`` format.
      Local (``file``/``jar``) locations and locations listed by the
      user-configured listing keep working.  Locations from a *nested* listing
      that are plain HTTP with no digest are ignored, because neither their
      certificate chain nor their content can be verified.

    Every accepted remote location without an explicit digest is registered as
    a trusted source, so the first successful retrieval pins its digest and
    later content substituted on the same URL is rejected.

    Any certificate failure while reading a listing, any signature/digest
    mismatch and any truncated download raise
    :class:`~volatility3.framework.exceptions.ResourceIntegrityError`; such a
    listing is never partially applied.
    """

    def __init__(
        self,
        location: str,
        trusted_key: Optional[str] = None,
        _depth: int = 0,
    ):
        if _depth > 5:
            raise ValueError("Remote identifier listings are nested too deeply")
        self._location = location
        self._depth = _depth
        self._trusted_key = trusted_key
        self._is_root = _depth == 0
        with resources.ResourceAccessor().open(url=location) as fp:
            try:
                self._data = json.load(fp)
            except ValueError as excp:
                raise exceptions.ResourceIntegrityError(
                    location, f"remote identifier list is not valid JSON: {excp}"
                ) from excp
        if not isinstance(self._data, dict):
            raise exceptions.ResourceIntegrityError(
                location, "remote identifier list is not a JSON object"
            )
        self._verify()

    def _verify(self) -> bool:
        self._verify_signature()
        version = self._data.get("version", 0)
        if version in [1, 2]:
            self._register_listed_digests()
            setattr(self, "process", getattr(self, f"process_v{version}"))
            return True
        raise ValueError("Unsupported version for remote identifier list format")

    def _register_listed_digests(self) -> None:
        """Registers a flat ``{location: digest}`` integrity map, if present."""
        hashes = self._data.get("hashes", {})
        if not isinstance(hashes, dict):
            raise exceptions.ResourceIntegrityError(
                self._location, "remote identifier list hashes are not a mapping"
            )
        for location, digest in hashes.items():
            try:
                resources.register_expected_hash(location, digest)
            except (TypeError, ValueError, exceptions.ResourceIntegrityError) as excp:
                vollog.warning(f"Rejecting remote digest for {location}: {excp}")

    def _verify_signature(self) -> None:
        signature = self._data.get("signature")
        if signature is None:
            if self._trusted_key:
                vollog.warning(
                    f"Remote identifier list {self._location} is not signed; "
                    "only entries carrying their own digests will be used"
                )
            return
        if not isinstance(signature, dict) or "signature" not in signature:
            raise exceptions.ResourceIntegrityError(
                self._location, "malformed signature block in remote identifier list"
            )
        if not self._trusted_key:
            raise exceptions.ResourceIntegrityError(
                self._location,
                "remote identifier list is signed but no trusted public key is configured",
            )
        unsigned = {k: v for k, v in self._data.items() if k != "signature"}
        payload = json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
        try:
            raw_signature = base64.b64decode(signature["signature"], validate=True)
        except (TypeError, ValueError) as excp:
            raise exceptions.ResourceIntegrityError(
                self._location, "malformed signature encoding in remote identifier list"
            ) from excp
        resources.verify_downloaded_signature(
            payload,
            raw_signature,
            self._trusted_key,
            signature.get("algorithm", "ed25519"),
            url=self._location,
        )

    @staticmethod
    def _split_entry(entry: Any) -> Optional[Tuple[str, Any]]:
        """Extracts ``(location, digest)`` from one listing entry.

        Returns None when the entry is not usable.
        """
        if isinstance(entry, str):
            return entry, None
        if isinstance(entry, dict):
            location = entry.get("location", entry.get("url", entry.get("path")))
            if location is None and len(entry) == 1:
                # {"https://...": "<digest>"} style
                location, digest = next(iter(entry.items()))
                return location, digest
            if location is None:
                return None
            digest = None
            for key in ("sha256", "sha384", "sha512", "hash", "digest"):
                if key in entry:
                    digest = entry[key]
                    if key in SUPPORTED_HASH_KEYS:
                        digest = f"{key}:{digest}"
                    break
            if digest is None and "algorithm" in entry:
                digest = f"{entry['algorithm']}:{entry.get('digest', '')}"
            return location, digest
        return None

    def _accept_entry(self, location: str, digest: Any) -> bool:
        """Checks an entry can be trusted, registering its expectation.

        An entry is trusted when any of the following holds:

        * it is a local (``file``/``jar``) location - a configured mirror,
        * it carries a digest, which is enforced on every retrieval,
        * the listing was signed with the configured key,
        * the entry itself is HTTPS (so its certificate chain is verified),
        * it is named by the listing the user configured.

        A trusted location without a digest is pinned on first use, so content
        substituted on the same URL later is rejected.  An entry from a nested
        listing that is plain HTTP and has no digest is rejected: neither its
        certificate chain nor its content can be verified.
        """
        parsed = urllib.parse.urlparse(location)
        local = parsed.scheme in ("", "file", "jar") or parsed.scheme not in (
            "http",
            "https",
            "ftp",
            "s3",
            "gs",
        )
        if digest is not None:
            try:
                resources.register_expected_hash(location, digest)
            except (TypeError, ValueError, exceptions.ResourceIntegrityError) as excp:
                vollog.warning(f"Rejecting remote identifier entry {location}: {excp}")
                return False
            return True
        if local:
            return True
        signed = self._trusted_key and self._data.get("signature") is not None
        if not (signed or parsed.scheme == "https" or self._is_root):
            vollog.warning(
                f"Ignoring remote identifier entry {location}: it is not HTTPS, "
                "carries no digest and the listing is not signed"
            )
            return False
        resources.register_trusted_source(location)
        return True

    def process(
        self, identifiers: Dict[bytes, List[str]], operating_system: Optional[str]
    ) -> Generator[Tuple[bytes, str], None, None]:
        raise ValueError("Identifier List version not verified")

    def process_v1(
        self,
        identifiers: Optional[Dict[bytes, List[str]]],
        operating_system: Optional[str],
    ) -> Generator[Tuple[bytes, str], None, None]:
        if operating_system in self._data:
            for identifier in self._data[operating_system]:
                try:
                    binary_identifier = base64.b64decode(identifier)
                except (TypeError, ValueError) as excp:
                    vollog.warning(
                        f"Skipping malformed identifier in {self._location}: {excp}"
                    )
                    continue
                for entry in self._data[operating_system][identifier]:
                    split = self._split_entry(entry)
                    if split is None:
                        continue
                    location, digest = split
                    if self._accept_entry(location, digest):
                        yield binary_identifier, location
        yield from self._process_additional(identifiers, operating_system)
        return identifiers

    def process_v2(
        self,
        identifiers: Optional[Dict[bytes, List[str]]],
        operating_system: Optional[str],
    ) -> Generator[Tuple[bytes, str], None, None]:
        if operating_system in self._data:
            entries = self._data[operating_system]
            if not isinstance(entries, dict):
                raise exceptions.ResourceIntegrityError(
                    self._location,
                    f"identifier section for {operating_system} is not a mapping",
                )
            for identifier, locations in entries.items():
                try:
                    binary_identifier = base64.b64decode(identifier)
                except (TypeError, ValueError) as excp:
                    vollog.warning(
                        f"Skipping malformed identifier in {self._location}: {excp}"
                    )
                    continue
                if isinstance(locations, (str, dict)):
                    locations = [locations]
                for entry in locations:
                    split = self._split_entry(entry)
                    if split is None:
                        vollog.warning(
                            f"Skipping malformed remote identifier entry for {binary_identifier!r}"
                        )
                        continue
                    location, digest = split
                    if self._accept_entry(location, digest):
                        yield binary_identifier, location
        yield from self._process_additional(identifiers, operating_system)
        return identifiers

    def _process_additional(
        self,
        identifiers: Optional[Dict[bytes, List[str]]],
        operating_system: Optional[str],
    ) -> Generator[Tuple[bytes, str], None, None]:
        for entry in self._data.get("additional", []):
            split = self._split_entry(entry)
            if split is None:
                continue
            location, digest = split
            if not self._accept_entry(location, digest):
                continue
            try:
                subrbf = RemoteIdentifierFormat(
                    location,
                    trusted_key=self._trusted_key,
                    _depth=self._depth + 1,
                )
                yield from subrbf.process(identifiers, operating_system)
            except exceptions.ResourceIntegrityError as excp:
                vollog.warning(
                    f"Rejected nested remote identifier list {location}: {excp}"
                )
            except OSError:
                vollog.debug(f"Remote file not found: {location}")
