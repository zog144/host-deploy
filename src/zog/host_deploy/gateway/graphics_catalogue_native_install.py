"""Root-owned entry point for the existing first Fonts catalogue installer.

The root administrator installs a *copy of the already verified* original
compiler evidence at the fixed local path. This module reads those files and
installed immutable source trees; it does not create approval records, pick a
generation, infer the newest output, query AWS or submit compiler work.

The signed receipt is verified by graphics_base_acceptance in install_native.
Root ownership alone does not prove the original producer ever verified a
generation: the protected installer must first authenticate that provenance.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat

from .. import image_build_lanes
from . import graphics_attester_import as importer
from . import graphics_catalogue_owner as catalogue

EVIDENCE_DIRECTORY = "/etc/zog/host-deploy/first-fonts-native"
EVIDENCE_NAME = "compiler-selection.json"
RECEIPT_NAME = "compiler-base-acceptance.json"
PIN_NAME = "october-commit-pin.py"
SCHEMA = "host-deploy-first-fonts-installed-native-evidence-v1"
SOURCE_SCHEMA = "host-deploy-first-fonts-installed-sources-v1"
IDENTITY_SCHEMA = "host-deploy-first-fonts-installed-host-identity-v1"
HEX64 = re.compile(r"[a-f0-9]{64}\Z")
COMMIT = re.compile(r"[a-f0-9]{40}\Z")
SHA = re.compile(r"sha256:[a-f0-9]{64}\Z")
FIELDS = {
    "schema", "lane_record", "accepted_base", "issuer_policy",
    "producer_binding", "origin_lane", "host_identity", "installed_sources",
}


class NativeCatalogueHeld(RuntimeError):
    pass


def _hold():
    raise NativeCatalogueHeld("first-fonts-native-evidence-unavailable") from None


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def _unique(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            _hold()
        result[name] = value
    return result


def _json(raw):
    try:
        value = json.loads(raw, object_pairs_hook=_unique,
                           parse_constant=lambda _: _hold())
        if type(value) is not dict or _canonical(value) != raw:
            _hold()
        return value
    except (ValueError, UnicodeError, TypeError, OverflowError):
        _hold()


def _read_exact(directory, filename, cap):
    """Read the fixed root-owned file without following any symlink."""
    if type(filename) is not str or "/" in filename or filename.startswith("."):
        _hold()
    fd = importer._protected(str(directory / filename), mode=0o600)
    try:
        st = os.fstat(fd)
        if not 0 < st.st_size <= cap:
            _hold()
        raw = os.read(fd, cap + 1)
        if len(raw) != st.st_size:
            _hold()
        after = os.fstat(fd)
        if (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            _hold()
        return raw
    finally:
        os.close(fd)


def _source_tree(root, expected):
    if (type(root) is not str or not root.startswith("/")
            or type(expected) is not str or SHA.fullmatch(expected) is None):
        _hold()
    fd = importer._protected(root, directory=True)
    try:
        before = os.fstat(fd)
        observed = "sha256:" + hashlib.sha256(
            _canonical(importer._inventory(root))).hexdigest()
        after = os.fstat(fd)
        if ((before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
                or observed != expected):
            _hold()
    finally:
        os.close(fd)
    return True


class RootReaders:
    """Real protected-file readers; no injected trust callbacks in main()."""

    def __init__(self):
        if os.geteuid() != 0:
            raise PermissionError("first Fonts catalogue installation requires root")
        directory = Path(EVIDENCE_DIRECTORY)
        fd = importer._protected(str(directory), directory=True, mode=0o700)
        os.close(fd)
        self.directory = directory
        self.raw = {
            name: _read_exact(directory, name, limit)
            for name, limit in (
                (EVIDENCE_NAME, 65536),
                (RECEIPT_NAME, 65536),
                (PIN_NAME, 65536),
            )
        }
        self.evidence = _json(self.raw[EVIDENCE_NAME])
        self.receipt = self.raw[RECEIPT_NAME]
        self.pin = self.raw[PIN_NAME]
        row = self.evidence
        if set(row) != FIELDS or row["schema"] != SCHEMA:
            _hold()
        identity = row["host_identity"]
        issuer = row["issuer_policy"]
        binding = row["producer_binding"]
        accepted = row["accepted_base"]
        installed_lane = row["lane_record"]
        if (type(identity) is not dict
                or set(identity) != {"schema", "host_id", "installation_id",
                                     "state_volume_id"}
                or identity["schema"] != IDENTITY_SCHEMA
                or type(issuer) is not dict or type(binding) is not dict
                or type(accepted) is not dict or type(installed_lane) is not dict
                or installed_lane.get("state") != "active"
                or type(installed_lane.get("specification")) is not dict
                or installed_lane.get("lane") !=
                   installed_lane["specification"].get("lane")
                or issuer.get("host_id") != identity["host_id"]
                or issuer.get("installation_id") != identity["installation_id"]
                or issuer.get("state_volume_id") != identity["state_volume_id"]
                or binding.get("host_id") != identity["host_id"]
                or binding.get("installation_id") != identity["installation_id"]
                or binding.get("state_volume_id") != identity["state_volume_id"]
                or accepted.get("generation_id") != binding.get("generation_id")
                or accepted.get("acceptance_receipt_sha256") !=
                   catalogue._sha(self.receipt)
                or binding.get("acceptance_receipt_sha256") !=
                   catalogue._sha(self.receipt)
                or installed_lane.get("schema") != image_build_lanes.INHERITED_SCHEMA):
            _hold()
        try:
            spec = image_build_lanes.validate(installed_lane["specification"])
            origin = image_build_lanes.validate(row["origin_lane"])
        except (ValueError, KeyError, TypeError, AttributeError):
            _hold()
        if (spec["schema"] != image_build_lanes.INHERITED_SCHEMA
                or spec["source_revision"] != catalogue.EXECUTABLE_SOURCE
                or spec["provenance_host_id"] != identity["host_id"]
                or origin["schema"] != image_build_lanes.SCHEMA
                or origin["provenance_host_id"] != identity["host_id"]
                or origin["provenance_project_id"] != issuer.get("project_id")
                or type(row["installed_sources"]) is not dict
                or row["installed_sources"].get("schema") != SOURCE_SCHEMA):
            _hold()
        sources = row["installed_sources"]
        if (type(sources) is not dict
                or set(sources) != {"schema", "roots"}
                or type(sources["roots"]) is not dict
                or set(sources["roots"]) != {
                    catalogue.SOURCE, catalogue.EXECUTABLE_SOURCE,
                    catalogue.READER_SOURCE}):
            _hold()
        self.sources = sources["roots"]
        for revision, source in self.sources.items():
            if (type(source) is not dict
                    or set(source) != {"root", "tree_sha256"}
                    or not COMMIT.fullmatch(revision)):
                _hold()

    def read_managed_lane(self, name):
        if name != self.evidence["lane_record"]["lane"]:
            _hold()
        return self.evidence["lane_record"]["specification"]

    def read_accepted_base(self, generation):
        row = self.evidence["accepted_base"]
        if generation != row["generation_id"]:
            _hold()
        return row

    def read_installed_pin(self, revision, name):
        if (revision, name) != (catalogue.SOURCE, catalogue.PIN_PATH):
            _hold()
        return self.pin

    def read_compiler_base_receipt(self, generation):
        self.read_accepted_base(generation)
        return self.receipt

    def read_compiler_base_issuer(self):
        return self.evidence["issuer_policy"]

    def read_compiler_base_binding(self, generation, digest):
        self.read_accepted_base(generation)
        if digest != catalogue._sha(self.receipt):
            _hold()
        return self.evidence["producer_binding"]

    def read_compiler_base_origin_lane(self, generation):
        self.read_accepted_base(generation)
        return self.evidence["origin_lane"]

    def attest_installed_source(self, revision):
        source = self.sources.get(revision)
        if source is None:
            return False
        return _source_tree(source["root"], source["tree_sha256"])

    def attest_host_identity(self, host, installation):
        row = self.evidence["host_identity"]
        return (host, installation) == (row["host_id"], row["installation_id"])

    def recheck(self):
        # Retained root-owned evidence must not change during publication.
        for name, original in self.raw.items():
            if _read_exact(self.directory, name, 65536) != original:
                _hold()
        for revision in self.sources:
            if not self.attest_installed_source(revision):
                _hold()


def install(*, lane, generation):
    """Only user selection is lane+generation; no path, revision or trust override."""
    if os.geteuid() != 0:
        raise PermissionError("first Fonts catalogue installation requires root")
    if (type(lane) is not str or not lane
            or type(generation) is not str or HEX64.fullmatch(generation) is None):
        _hold()
    readers = RootReaders()
    if (readers.evidence["lane_record"]["lane"] != lane
            or readers.evidence["accepted_base"]["generation_id"] != generation):
        _hold()
    result = catalogue.install_native(
        lane_name=lane,
        generation_id=generation,
        read_managed_lane=readers.read_managed_lane,
        read_accepted_base=readers.read_accepted_base,
        read_installed_pin=readers.read_installed_pin,
        attest_installed_source=readers.attest_installed_source,
        attest_host_identity=readers.attest_host_identity,
        read_compiler_base_receipt=readers.read_compiler_base_receipt,
        read_compiler_base_issuer=readers.read_compiler_base_issuer,
        read_compiler_base_binding=readers.read_compiler_base_binding,
        read_compiler_base_origin_lane=readers.read_compiler_base_origin_lane,
        # Separate shared-Project owner capability is not yet installed:
        # distinct lane names on a shared Project must HOLD.
    )
    readers.recheck()
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description="Root-owned first Fonts catalogue installer")
    parser.add_argument("--lane", required=True)
    parser.add_argument("--generation", required=True)
    args = parser.parse_args(argv)
    result = install(lane=args.lane, generation=args.generation)
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
