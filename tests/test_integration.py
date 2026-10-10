"""Exercise the native CLI using synthetic and real PostgreSQL WAL."""

import argparse
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest

from wal_fixtures import (
    PAGE_SIZE, SEGMENT_SIZE, WalFixture, block_header, main_body,
)


BINARY = Path(os.environ.get("AUDIT_BINARY", "build/pg18/documentdb-wal-audit")).resolve()
PG_MAJOR = int(os.environ.get("PG_MAJOR", "18"))
PG_BIN = Path(os.environ.get("PG_BIN", f"/usr/lib/postgresql/{PG_MAJOR}/bin"))


def lsn(value):
    return f"{value >> 32:X}/{value & 0xFFFFFFFF:X}"


def bson_ints(**fields):
    body = b"".join(
        b"\x10" + key.encode("ascii") + b"\0" + struct.pack("<i", value)
        for key, value in fields.items()
    ) + b"\0"
    return struct.pack("<i", len(body) + 4) + body


def ordinary_tuple(identifier=1, value=2):
    result = struct.pack("<HHB", 3, 0, 24) + b"\0" + struct.pack("<q", 0)
    for bson in (bson_ints(**{"": identifier}), bson_ints(_id=identifier, value=value)):
        while (23 + len(result) - 5) % 4:
            result += b"\0"
        result += struct.pack("<I", (len(bson) + 4) << 2) + bson
    return result


def key_tuple(identifier=1, shard_key=True, short_header=False, creation_time=False):
    bitmap = 3 if shard_key else 2
    result = struct.pack("<HHB", 4 if creation_time else 3, 1, 24) + bytes((bitmap,))
    if shard_key:
        result += struct.pack("<q", 0)
    bson = bson_ints(**{"": identifier})
    if short_header:
        result += bytes((((len(bson) + 1) << 1) | 1,)) + bson
    else:
        while (23 + len(result) - 5) % 4:
            result += b"\0"
        result += struct.pack("<I", (len(bson) + 4) << 2) + bson
    return result


def heap_body(payload=None, main=None, flags=0x20, block_number=0):
    payload = ordinary_tuple() if payload is None else payload
    main = struct.pack("<HB", 1, 0) if main is None else main
    if not payload:
        flags &= ~0x20
    return (
        block_header(flags=flags, data_size=len(payload), number=block_number)
        + bytes((255, len(main))) + payload + main
    )

def catalog_tuple(database, collection, collection_id, is_view=False):
    natts = 10
    hoff = 32
    bitmap = (1 << 0) | (1 << 1) | (1 << 2)
    if is_view:
        bitmap |= 1 << 5
    data = bytearray(struct.pack("<H", bitmap) + b"\0" * (hoff - 23 - 2))
    for value in (database.encode(), collection.encode()):
        data += bytes(((len(value) + 1) * 2 + 1,)) + value
    while (23 + len(data)) % 8:
        data += b"\0"
    data += struct.pack("<q", collection_id)
    if is_view:
        data += bytes((13,)) + b"\x05\0\0\0\0"
    return struct.pack("<HHB", natts, 1, hoff) + data


def commit_data(timestamp=0):
    return struct.pack("<q", timestamp)


class CliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="wal-audit-tests-")
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.fixture = WalFixture(self.directory / "wal", major=PG_MAJOR)

    def run_cli(self, *args, success=True):
        result = subprocess.run(
            [str(BINARY), *map(str, args)], text=True, capture_output=True, timeout=30,
        )
        self.assertNotRegex(
            result.stderr,
            r"AddressSanitizer|LeakSanitizer|UndefinedBehaviorSanitizer|runtime error:",
        )
        if success:
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        else:
            self.assertIn(result.returncode, (1, 2), result.stderr + result.stdout)
        return result

    def output(self, *args, success=True, fixture=None):
        paths = (fixture or self.fixture).write()
        result = self.run_cli("--format", "jsonl", *args, *paths, success=success)
        events = [json.loads(line) for line in result.stdout.splitlines() if line]
        return result, events

    def manifest(self, valid_from="0/0", valid_to="FFFFFFFF/FFFFFFFF"):
        path = self.directory / "manifest.json"
        path.write_text(json.dumps({
            "schemaVersion": 1,
            "postgresMajor": PG_MAJOR,
            "systemIdentifier": "12345",
            "timeline": 1,
            "documentdbVersion": "ordinary-bson-v1",
            "validFromLsn": valid_from,
            "validToLsn": valid_to,
            "relations": [{
                "tblspaceOid": 1663, "databaseOid": 5, "relfilenode": 42,
                "collectionId": 42, "database": "test", "collection": "documents",
            }],
        }), encoding="utf-8")
        return path

    def catalog_manifest(self, valid_from="0/0",
                         valid_to="FFFFFFFF/FFFFFFFF"):
        path = self.directory / "catalog-manifest.json"
        path.write_text(json.dumps({
            "schemaVersion": 2,
            "postgresMajor": PG_MAJOR,
            "systemIdentifier": "12345",
            "timeline": 1,
            "documentdbVersion": "1.0-0",
            "validFromLsn": valid_from,
            "validToLsn": valid_to,
            "relations": [{
                "kind": "collections_catalog",
                "tblspaceOid": 1663, "databaseOid": 5, "relfilenode": 42,
            }],
        }), encoding="utf-8")
        return path

    def state_manifest(self):
        path = self.directory / "state-manifest.json"
        path.write_text(json.dumps({
            "schemaVersion": 2,
            "postgresMajor": PG_MAJOR,
            "systemIdentifier": "12345",
            "timeline": 1,
            "documentdbVersion": "1.0-0",
            "validFromLsn": "0/0",
            "validToLsn": "FFFFFFFF/FFFFFFFF",
            "relations": [
                {
                    "kind": "document",
                    "tblspaceOid": 1663, "databaseOid": 5,
                    "relfilenode": 42, "collectionId": 42,
                    "database": "test", "collection": "documents",
                },
                {
                    "kind": "collections_catalog",
                    "tblspaceOid": 1663, "databaseOid": 5,
                    "relfilenode": 43,
                },
            ],
        }), encoding="utf-8")
        return path

    def catalog_insert(self, xid, tuple_bytes, offnum, block=0):
        main = struct.pack("<HB", offnum, 0)
        return self.fixture.append(
            body=heap_body(tuple_bytes, main=main, block_number=block),
            xid=xid, rmid=10,
        )

    def catalog_delete(self, xid, offnum, block=0, old_tuple=None):
        flags = 1 if old_tuple is not None else 0
        main = struct.pack("<IHBB", 10, offnum, 0, flags)
        if old_tuple is not None:
            main += old_tuple
        return self.fixture.append(
            body=heap_body(b"", main=main, block_number=block),
            xid=xid, rmid=10, info=0x10,
        )

    def insert_and_commit(self, xid=10, payload=None):
        start = self.fixture.append(body=heap_body(payload), xid=xid, rmid=10)
        end = self.fixture.append(commit_data(), xid=xid, rmid=1, info=0)
        return start, end

    def test_help_and_matching_version(self):
        self.assertIn("wal", self.run_cli("--help").stdout.lower())
        self.assertIn(str(PG_MAJOR), self.run_cli("--version").stdout)

    def test_invalid_arguments(self):
        for args in (
            (), ("--postgres-major", "15"), ("--format", "xml"),
            ("--from-lsn", "-1/0"), ("--from-lsn", "1/100000000"),
            ("--transaction", "-1"), ("--transaction", "10oops"),
            ("--max-record-bytes", "-1"), ("--max-transaction-bytes", "0"),
            ("--max-document-bytes", "0"), ("--unknown",),
            ("--pgdata", "/missing"), ("--best-effort",),
        ):
            with self.subTest(args=args):
                self.run_cli(*args, success=False)

    def test_wrong_compiled_major_rejected(self):
        alternate = 17 if PG_MAJOR == 18 else 18
        self.run_cli("--postgres-major", alternate, success=False)

    def test_wrong_wal_major_rejected(self):
        alternate = 17 if PG_MAJOR == 18 else 18
        fixture = WalFixture(self.directory / "other", major=alternate)
        fixture.append(b"opaque", rmid=21)
        self.output("--show-postgres-records", fixture=fixture, success=False)

    def test_physical_record_jsonl(self):
        self.fixture.append(b"opaque", rmid=21)
        _, events = self.output("--show-postgres-records")
        self.assertTrue(events)
        self.assertTrue(any(e.get("certainty") == "physical" for e in events))

    def test_manifest_bson_insert_commits(self):
        _, commit = self.insert_and_commit()
        _, events = self.output("--manifest", self.manifest())
        inserts = [e for e in events if e.get("operation") == "insert"]
        self.assertEqual(len(inserts), 1)
        self.assertEqual(inserts[0]["commitLsn"], lsn(commit))
        self.assertEqual(inserts[0]["collectionId"], 42)
        self.assertIsNotNone(inserts[0]["after"])
        self.assertEqual(inserts[0]["after"]["value"], {"$numberInt": "2"})

    def test_redaction_suppresses_all_document_identifiers(self):
        self.insert_and_commit(payload=ordinary_tuple(identifier=1852797049, value=123456789))
        result, events = self.output("--manifest", self.manifest(), "--redact-documents")
        self.assertNotIn("1852797049", result.stdout + result.stderr)
        self.assertNotIn("123456789", result.stdout + result.stderr)
        for event in events:
            self.assertIsNone(event.get("objectId"))
            self.assertIsNone(event.get("before"))
            self.assertIsNone(event.get("after"))

    def test_aborted_changes_excluded(self):
        self.fixture.append(body=heap_body(), xid=10, rmid=10)
        self.fixture.append(commit_data(), xid=10, rmid=1, info=0x20)
        _, events = self.output("--manifest", self.manifest())
        self.assertFalse(any(e.get("operation") == "insert" for e in events))
        _, included = self.output("--manifest", self.manifest(), "--include-aborted")
        self.assertTrue(any(e.get("operation") == "insert" for e in included))

    def test_interleaved_transactions_follow_commit_order(self):
        self.fixture.append(body=heap_body(), xid=10, rmid=10)
        self.fixture.append(body=heap_body(), xid=11, rmid=10)
        self.fixture.append(commit_data(), xid=11, rmid=1)
        self.fixture.append(commit_data(), xid=10, rmid=1)
        _, events = self.output("--manifest", self.manifest())
        inserts = [e for e in events if e.get("operation") == "insert"]
        self.assertEqual([e["transactionId"] for e in inserts], [11, 10])

    def test_subtransaction_committed_with_parent(self):
        self.fixture.append(body=heap_body(), xid=11, rmid=10)
        assignment = struct.pack("<III", 10, 1, 11)
        self.fixture.append(assignment, xid=10, rmid=1, info=0x50)
        self.fixture.append(
            commit_data() + struct.pack("<III", 2, 1, 11),
            xid=10, rmid=1, info=0x80,
        )
        _, events = self.output("--manifest", self.manifest())
        inserts = [e for e in events if e.get("operation") == "insert"]
        self.assertEqual(len(inserts), 1)
        self.assertEqual(inserts[0]["transactionId"], 10)

    def test_aborted_child_not_emitted_at_parent_commit(self):
        self.fixture.append(body=heap_body(), xid=11, rmid=10)
        self.fixture.append(commit_data(), xid=11, rmid=1, info=0x20)
        self.fixture.append(body=heap_body(), xid=10, rmid=10)
        self.fixture.append(commit_data(), xid=10, rmid=1)
        _, events = self.output("--manifest", self.manifest())
        inserts = [e for e in events if e.get("operation") == "insert"]
        self.assertEqual(len(inserts), 1)
        self.assertEqual(inserts[0]["transactionId"], 10)

    def test_known_savepoint_abort_is_not_a_top_level_summary(self):
        self.fixture.append(struct.pack("<III", 10, 1, 11), xid=10, rmid=1, info=0x50)
        self.fixture.append(body=heap_body(), xid=11, rmid=10)
        self.fixture.append(commit_data(), xid=11, rmid=1, info=0x20)
        self.fixture.append(body=heap_body(), xid=10, rmid=10)
        self.fixture.append(commit_data(), xid=10, rmid=1)
        _, events = self.output("--manifest", self.manifest())
        summaries = [e for e in events if e.get("eventType") == "transaction"]
        self.assertEqual([e["transactionId"] for e in summaries], [10])
        _, events = self.output("--manifest", self.manifest(), "--include-aborted",
                                "--transaction", 10)
        inserts = [e for e in events if e.get("operation") == "insert"]
        self.assertEqual([e["transactionId"] for e in inserts], [11, 10])
        self.assertEqual(inserts[0]["outcome"], "aborted")
        self.assertEqual(inserts[0]["parentTransactionId"], 10)

    def test_logged_old_key_recovers_identifier_without_document(self):
        for operation in ("delete", "update"):
            for shard in (False, True):
                with self.subTest(operation=operation, shard_key=shard):
                    fixture = WalFixture(self.directory / f"{operation}-{shard}", major=PG_MAJOR)
                    old_key = key_tuple(identifier=99, shard_key=shard)
                    if operation == "delete":
                        main = struct.pack("<IHBB", 10, 1, 0, 4) + old_key
                        info = 0x10
                    else:
                        main = struct.pack("<IHBBIH", 10, 1, 0, 8, 10, 2) + old_key
                        info = 0x20
                    fixture.append(body=heap_body(payload=b"", main=main),
                                   xid=10, rmid=10, info=info)
                    fixture.append(commit_data(), xid=10, rmid=1)
                    _, events = self.output("--manifest", self.manifest(), fixture=fixture)
                    changes = [e for e in events if e.get("operation") == operation]
                    self.assertEqual(len(changes), 1)
                    self.assertEqual(changes[0]["objectId"], {"_id": {"$numberInt": "99"}})
                    self.assertIsNone(changes[0]["before"])
                    self.assertEqual(changes[0]["certainty"], "incomplete")
                    _, redacted = self.output("--manifest", self.manifest(),
                                              "--redact-documents", fixture=fixture)
                    self.assertTrue(all(e.get("objectId") is None for e in redacted))
                    self.output("--manifest", self.manifest(), "--strict",
                                fixture=fixture, success=False)

    def test_delete_without_old_tuple_is_explicitly_incomplete(self):
        delete = struct.pack("<IHBB", 10, 1, 0, 0)
        self.fixture.append(body=heap_body(payload=b"", main=delete), xid=10,
                            rmid=10, info=0x10)
        self.fixture.append(commit_data(), xid=10, rmid=1)
        _, events = self.output("--manifest", self.manifest())
        deletes = [e for e in events if e.get("operation") == "delete"]
        self.assertEqual(len(deletes), 1)
        self.assertEqual(deletes[0]["certainty"], "incomplete")
        self.assertIsNone(deletes[0]["before"])

    def test_new_update_tuple_available(self):
        update = struct.pack("<IHBBIH", 10, 1, 0, 0x10, 10, 2)
        self.fixture.append(
            body=heap_body(ordinary_tuple(value=789), main=update),
            xid=10, rmid=10, info=0x20,
        )
        self.fixture.append(commit_data(), xid=10, rmid=1)
        _, events = self.output("--manifest", self.manifest())
        updates = [e for e in events if e.get("operation") == "update"]
        self.assertEqual(len(updates), 1)
        self.assertEqual(updates[0]["after"]["value"], {"$numberInt": "789"})

    def test_heap_multi_insert_reconstructs_each_ordinary_tuple(self):
        payload = b""
        for identifier in (101, 102):
            if len(payload) % 2:
                payload += b"\0"
            single = ordinary_tuple(identifier=identifier)
            infomask2, infomask, hoff = struct.unpack_from("<HHB", single)
            payload += struct.pack("<HHHB", len(single) - 5, infomask2, infomask, hoff)
            payload += single[5:]
        main = struct.pack("<BxH", 8, 2)
        self.fixture.append(body=heap_body(payload, main=main),
                            xid=10, rmid=9, info=0xD0)
        self.fixture.append(commit_data(), xid=10, rmid=1)
        _, events = self.output("--manifest", self.manifest())
        inserts = [e for e in events if e.get("operation") == "insert"]
        self.assertEqual(len(inserts), 2)
        self.assertEqual(
            [e["after"]["_id"] for e in inserts],
            [{"$numberInt": "101"}, {"$numberInt": "102"}],
        )

    def test_catalog_lifecycle_from_committed_wal(self):
        sentinel = catalog_tuple("audit", "system.dbSentinel", 6400)
        created = catalog_tuple("audit", "items", 6401)
        self.catalog_insert(10, sentinel, 1)
        creation_lsn = self.catalog_insert(10, created, 2)
        commit = self.fixture.append(commit_data(), xid=10, rmid=1)
        _, events = self.output("--manifest", self.catalog_manifest())
        lifecycle = [e for e in events if e.get("eventType") == "catalog"]
        self.assertEqual([e["operation"] for e in lifecycle],
                         ["databaseCreate", "collectionCreate"])
        self.assertEqual(lifecycle[0]["eventLsn"], lsn(creation_lsn))
        self.assertEqual(lifecycle[0]["commitLsn"], lsn(commit))
        self.assertEqual(lifecycle[0]["after"]["database"], "audit")
        self.assertEqual(lifecycle[1]["after"]["collection"], "items")
        self.assertEqual(lifecycle[1]["certainty"], "inferred")
        self.assertEqual(lifecycle[1]["coverage"], "row-local")
        self.assertEqual(lifecycle[1]["evidence"],
                         ["collections_catalog_insert"])
        self.assertNotIn("command", lifecycle[1])

    def test_catalog_abort_and_subtransaction_folding(self):
        created = catalog_tuple("audit", "items", 6401)
        self.catalog_insert(11, created, 2)
        self.fixture.append(struct.pack("<III", 10, 1, 11),
                            xid=10, rmid=1, info=0x50)
        self.fixture.append(commit_data() + struct.pack("<III", 2, 1, 11),
                            xid=10, rmid=1, info=0x80)
        self.catalog_insert(12, catalog_tuple("audit", "aborted", 6402), 3)
        self.fixture.append(commit_data(), xid=12, rmid=1, info=0x20)
        _, events = self.output("--manifest", self.catalog_manifest(),
                                "--include-aborted")
        lifecycle = [e for e in events if e.get("eventType") == "catalog"]
        self.assertEqual(len(lifecycle), 1)
        self.assertEqual(lifecycle[0]["operation"], "collectionCreate")
        self.assertEqual(lifecycle[0]["transactionId"], 10)
        self.assertEqual(lifecycle[0]["collection"], "items")

    def test_catalog_multi_insert_and_filter(self):
        tuples = [
            catalog_tuple("audit", "system.dbSentinel", 6400),
            catalog_tuple("audit", "items", 6401),
        ]
        payload = b""
        for value in tuples:
            if len(payload) % 2:
                payload += b"\0"
            infomask2, infomask, hoff = struct.unpack_from("<HHB", value)
            payload += struct.pack("<HHHB", len(value) - 5,
                                   infomask2, infomask, hoff) + value[5:]
        main = struct.pack("<BxH", 8, 2)
        self.fixture.append(body=heap_body(payload, main=main),
                            xid=10, rmid=9, info=0xD0)
        self.fixture.append(commit_data(), xid=10, rmid=1)
        _, hidden = self.output("--manifest", self.catalog_manifest(),
                                "--transaction", 11)
        self.assertFalse(any(e.get("eventType") == "catalog" for e in hidden))
        _, events = self.output("--manifest", self.catalog_manifest())
        self.assertEqual(
            [e["operation"] for e in events if e.get("eventType") == "catalog"],
            ["databaseCreate", "collectionCreate"],
        )

    def test_catalog_range_builds_state_before_output_boundary(self):
        created = catalog_tuple("audit", "items", 6401)
        insert_lsn = self.catalog_insert(10, created, 2)
        self.fixture.append(commit_data(), xid=10, rmid=1)
        delete_lsn = self.catalog_delete(11, 2)
        self.fixture.append(commit_data(), xid=11, rmid=1)
        _, events = self.output("--manifest", self.catalog_manifest(),
                                "--from-lsn", lsn(delete_lsn))
        lifecycle = [e for e in events if e.get("eventType") == "catalog"]
        self.assertEqual([e["operation"] for e in lifecycle],
                         ["collectionDrop"])
        self.assertEqual(lifecycle[0]["before"]["collection"], "items")
        self.assertFalse(any(e.get("eventLsn") == lsn(insert_lsn)
                             for e in lifecycle))

    def test_catalog_strict_rejects_incomplete_delete(self):
        self.catalog_delete(10, 99, block=7)
        self.fixture.append(commit_data(), xid=10, rmid=1)
        _, events = self.output("--manifest", self.catalog_manifest(),
                                "--strict", success=False)
        unknown = [e for e in events if e.get("eventType") == "catalog"]
        self.assertEqual(len(unknown), 1)
        self.assertEqual(unknown[0]["operation"], "unknown")
        self.assertEqual(unknown[0]["certainty"], "incomplete")
        self.assertEqual(unknown[0]["warnings"],
                         ["catalog_delete_state_missing"])

    def test_catalog_cache_modes_and_private_cleanup(self):
        self.catalog_insert(10, catalog_tuple("audit", "items", 6401), 2)
        self.fixture.append(commit_data(), xid=10, rmid=1)
        paths = self.fixture.write()
        manifest = self.catalog_manifest()
        cache = self.directory / "catalog.sqlite"
        first = self.run_cli("--format", "jsonl", "--manifest", manifest,
                             "--cache", cache, *paths)
        self.assertTrue(cache.exists())
        self.assertEqual(cache.stat().st_mode & 0o777, 0o600)
        second = self.run_cli("--format", "jsonl", "--manifest", manifest,
                              "--cache", cache, *paths)
        self.assertTrue(any(json.loads(line).get("eventType") == "catalog"
                            for line in first.stdout.splitlines()))
        self.assertFalse(any(json.loads(line).get("eventType") == "catalog"
                             for line in second.stdout.splitlines()))
        rebuilt = self.run_cli("--format", "jsonl", "--manifest", manifest,
                               "--cache", cache, "--rebuild-cache", *paths)
        self.assertTrue(any(json.loads(line).get("eventType") == "catalog"
                            for line in rebuilt.stdout.splitlines()))
        ephemeral = self.directory / "ephemeral"
        ephemeral.mkdir(mode=0o700)
        self.run_cli("--format", "jsonl", "--manifest", manifest,
                     "--ephemeral-cache", ephemeral, *paths)
        self.assertEqual(list(ephemeral.iterdir()), [])
        self.run_cli("--format", "jsonl", "--manifest", manifest,
                     "--no-persistent-cache", *paths)

    def test_prefix_update_reconstructs_after_from_page_state(self):
        old = ordinary_tuple(identifier=1, value=2)
        new = ordinary_tuple(identifier=1, value=789)
        self.fixture.append(body=heap_body(old, main=struct.pack("<HB", 1, 0)),
                            xid=9, rmid=10)
        self.fixture.append(commit_data(), xid=9, rmid=1)
        prefix = 12
        delta = struct.pack("<H", prefix) + new[:6] + new[6 + prefix:]
        update = struct.pack("<IHBBIH", 10, 1, 0, 0x20, 10, 2)
        self.fixture.append(
            body=heap_body(delta, main=update),
            xid=10, rmid=10, info=0x20,
        )
        self.fixture.append(commit_data(), xid=10, rmid=1)
        cache = self.directory / "state-cache.sqlite"
        _, events = self.output("--manifest", self.state_manifest(),
                                "--cache", cache)
        updates = [e for e in events if e.get("operation") == "update"]
        self.assertEqual(len(updates), 1)
        self.assertEqual(updates[0]["certainty"], "incomplete")
        self.assertEqual(updates[0]["objectId"], {"_id": {"$numberInt": "1"}})
        self.assertEqual(updates[0]["after"]["value"], {"$numberInt": "789"})
        self.assertTrue(updates[0]["reconstruction"]["usedPrefix"])
        _, replayed = self.output("--manifest", self.state_manifest(),
                                  "--cache", cache)
        replayed_update = next(
            e for e in replayed if e.get("operation") == "update")
        self.assertEqual(replayed_update["objectId"], updates[0]["objectId"])
        self.assertEqual(replayed_update["after"], updates[0]["after"])

    def test_prefix_update_missing_state_is_explicitly_incomplete(self):
        update = struct.pack("<IHBBIH", 10, 1, 0, 0x20, 10, 2)
        self.fixture.append(
            body=heap_body(struct.pack("<H", 8) + ordinary_tuple(), main=update),
            xid=10, rmid=10, info=0x20,
        )
        self.fixture.append(commit_data(), xid=10, rmid=1)
        ephemeral = self.directory / "missing-cache"
        ephemeral.mkdir(mode=0o700)
        _, events = self.output("--manifest", self.state_manifest(),
                                "--ephemeral-cache", ephemeral)
        update_event = next(e for e in events if e.get("operation") == "update")
        self.assertIsNone(update_event["after"])
        self.assertEqual(update_event["warnings"], ["update_base_tid_missing"])

    def test_malformed_prefix_delta_is_explicitly_incomplete(self):
        update = struct.pack("<IHBBIH", 10, 1, 0, 0x20, 10, 2)
        self.fixture.append(body=heap_body(b"\x08", main=update),
                            xid=10, rmid=10, info=0x20)
        self.fixture.append(commit_data(), xid=10, rmid=1)
        ephemeral = self.directory / "malformed-cache"
        ephemeral.mkdir(mode=0o700)
        _, events = self.output("--manifest", self.state_manifest(),
                                "--ephemeral-cache", ephemeral)
        update_event = next(e for e in events if e.get("operation") == "update")
        self.assertIsNone(update_event["after"])
        self.assertEqual(update_event["warnings"], ["update_delta_malformed"])

    def test_unresolved_transaction_is_not_success(self):
        self.fixture.append(body=heap_body(), xid=10, rmid=10)
        _, events = self.output("--manifest", self.manifest(), success=False)
        self.assertTrue(any(e.get("certainty") == "incomplete" for e in events))

    def test_filtered_unrelated_unresolved_transaction_still_fails(self):
        self.insert_and_commit(xid=10)
        self.fixture.append(body=heap_body(), xid=11, rmid=10)
        result, _ = self.output("--manifest", self.manifest(), "--transaction", 10,
                                success=False)
        self.assertEqual(result.returncode, 1)
        self.assertIn("unresolved transaction", result.stderr)

    def test_unresolved_known_child_reports_only_parent_summary(self):
        self.fixture.append(struct.pack("<III", 10, 1, 11), xid=10, rmid=1, info=0x50)
        self.fixture.append(body=heap_body(), xid=11, rmid=10)
        _, events = self.output("--manifest", self.manifest(), "--transaction", 11,
                                success=False)
        summaries = [e for e in events if e.get("eventType") == "transaction"]
        self.assertEqual([e["transactionId"] for e in summaries], [10])

    def test_strict_ignores_unrequested_incomplete_effects(self):
        self.fixture.append(body=heap_body(payload=b""), xid=11, rmid=10)
        self.fixture.append(commit_data(), xid=11, rmid=1, info=0x20)
        self.insert_and_commit(xid=10)
        self.fixture.append(body=heap_body(payload=b""), xid=12, rmid=10)
        self.fixture.append(commit_data(), xid=12, rmid=1)
        self.output("--manifest", self.manifest(), "--transaction", 10, "--strict")

    def test_strict_missing_document_fails(self):
        self.insert_and_commit(payload=b"")
        _, events = self.output("--manifest", self.manifest(), "--strict", success=False)
        self.assertTrue(any(e.get("certainty") == "incomplete" for e in events))

    def test_invalid_bson_is_incomplete_not_document(self):
        payload = bytearray(ordinary_tuple())
        payload[-1] = 0xFF
        self.insert_and_commit(payload=bytes(payload))
        _, events = self.output("--manifest", self.manifest(), "--strict", success=False)
        self.assertFalse(any(e.get("after") is not None for e in events))

    def test_manifest_cluster_mismatch(self):
        self.insert_and_commit()
        path = self.manifest()
        document = json.loads(path.read_text())
        document["systemIdentifier"] = "99999"
        path.write_text(json.dumps(document))
        self.output("--manifest", path, success=False)

    def test_manifest_invalid_numeric_type(self):
        self.insert_and_commit()
        path = self.manifest()
        document = json.loads(path.read_text())
        document["relations"][0]["relfilenode"] = 42.5
        path.write_text(json.dumps(document))
        self.output("--manifest", path, success=False)

    def test_manifest_expired_does_not_name_relation(self):
        self.insert_and_commit()
        _, events = self.output("--manifest", self.manifest(valid_to="0/10"))
        self.assertFalse(any(e.get("collection") == "documents" for e in events))

    def test_crc_failure_header_and_body(self):
        for offset in (4, 25):
            with self.subTest(offset=offset):
                fixture = WalFixture(self.directory / f"crc-{offset}", major=PG_MAJOR)
                start = fixture.append(b"opaque", rmid=21)
                fixture.segments[1][start % SEGMENT_SIZE + offset] ^= 1
                self.output("--show-postgres-records", fixture=fixture, success=False)

    def test_previous_record_link_checked(self):
        self.fixture.append(b"first", rmid=21)
        self.fixture.append(b"next", rmid=21, previous_lsn=1)
        self.output("--show-postgres-records", success=False)

    def test_cross_page_and_segment_records(self):
        self.fixture.append(b"x" * (SEGMENT_SIZE + PAGE_SIZE), rmid=21)
        self.fixture.append(b"after", rmid=21)
        _, events = self.output("--show-postgres-records")
        records = [e for e in events if e.get("certainty") == "physical"]
        self.assertGreaterEqual(len(records), 2)

    def test_segment_switch_skips_unused_tail(self):
        self.fixture.append(rmid=0, info=0x40)
        self.fixture.append(b"after switch", rmid=21)
        self.output("--show-postgres-records")

    def test_segment_gap_and_duplicate(self):
        self.fixture.append(rmid=0, info=0x40)
        self.fixture.append(rmid=0, info=0x40)
        self.fixture.append(b"last", rmid=21)
        paths = self.fixture.write()
        self.run_cli(paths[0], paths[2], success=False)
        self.run_cli(paths[0], paths[0], success=False)

    def test_mixed_cluster_rejected(self):
        self.fixture.append(rmid=0, info=0x40)
        self.fixture.append(b"last", rmid=21)
        self.fixture.segments[2][24:32] = struct.pack("<Q", 9876)
        self.output("--show-postgres-records", success=False)

    def test_truncated_segment_rejected(self):
        paths = self.fixture.write()
        paths[0].write_bytes(paths[0].read_bytes()[:100])
        self.run_cli(paths[0], success=False)

    def test_record_size_bound(self):
        self.fixture.append(b"x" * 4096, rmid=21)
        self.output("--max-record-bytes", 1024, "--show-postgres-records", success=False)

    def test_malformed_transaction_payloads_fail_without_crashing(self):
        cases = (
            (0x00, b"\0" * 7),
            (0x20, b"\0" * 7),
            (0x50, struct.pack("<II", 10, 0x7FFFFFFF)),
            (0x50, struct.pack("<II", 10, 0xFFFFFFFF)),
            (0x80, commit_data() + struct.pack("<II", 2, 0x7FFFFFFF)),
            (0x80, commit_data() + struct.pack("<II", 2, 0xFFFFFFFF)),
            (0x10, b"\0"),
            (0x30, b"\0"),
            (0x40, b"\0"),
        )
        for index, (info, payload) in enumerate(cases):
            with self.subTest(info=info, index=index):
                fixture = WalFixture(self.directory / f"bad-xact-{index}", major=PG_MAJOR)
                fixture.append(payload, xid=10, rmid=1, info=info)
                self.output(fixture=fixture, success=False)

    def test_huge_declared_record_rejected_before_reading_body(self):
        self.fixture.append(b"record", rmid=21)
        struct.pack_into("<I", self.fixture.segments[1], 40, 1020 * 1024 * 1024)
        self.output("--max-record-bytes", 1024, success=False)

    def test_lsn_range_and_transaction_filter(self):
        first, _ = self.insert_and_commit(xid=10)
        second, _ = self.insert_and_commit(xid=11)
        _, events = self.output("--manifest", self.manifest(), "--from-lsn", lsn(second))
        inserts = [e for e in events if e.get("operation") == "insert"]
        self.assertEqual([e["transactionId"] for e in inserts], [11])
        _, events = self.output("--manifest", self.manifest(), "--transaction", 10)
        inserts = [e for e in events if e.get("operation") == "insert"]
        self.assertEqual([e["transactionId"] for e in inserts], [10])
        self.assertLess(first, second)

    def test_upper_lsn_boundary_is_exclusive(self):
        self.insert_and_commit(xid=10)
        second, _ = self.insert_and_commit(xid=11)
        _, events = self.output("--manifest", self.manifest(), "--to-lsn", lsn(second))
        inserts = [e for e in events if e.get("operation") == "insert"]
        self.assertEqual([e["transactionId"] for e in inserts], [10])

    def test_output_is_deterministic(self):
        self.insert_and_commit()
        first, _ = self.output("--manifest", self.manifest())
        second, _ = self.output("--manifest", self.manifest())
        self.assertEqual(first.stdout, second.stdout)

    def test_inputs_remain_unchanged(self):
        self.insert_and_commit()
        paths = self.fixture.write()
        before = {path.name: path.read_bytes() for path in paths}
        self.run_cli("--manifest", self.manifest(), *paths)
        self.assertEqual({path.name: path.read_bytes() for path in paths}, before)

    def test_spill_matches_memory_and_cleans_files(self):
        for i in range(100):
            self.fixture.append(body=heap_body(ordinary_tuple(value=i)), xid=10, rmid=10)
        self.fixture.append(commit_data(), xid=10, rmid=1)
        _, expected = self.output("--manifest", self.manifest())
        spill = self.directory / "spill"
        spill.mkdir(mode=0o700)
        _, actual = self.output(
            "--manifest", self.manifest(), "--max-transaction-bytes", 4096,
            "--spill-dir", spill,
        )
        self.assertEqual(actual, expected)
        self.assertEqual(list(spill.iterdir()), [])

    def test_memory_limit_without_spill_fails(self):
        for _ in range(100):
            self.fixture.append(body=heap_body(), xid=10, rmid=10)
        self.fixture.append(commit_data(), xid=10, rmid=1)
        self.output("--manifest", self.manifest(), "--max-transaction-bytes", 4096, success=False)

    def test_directory_mode(self):
        self.insert_and_commit()
        self.fixture.write()
        self.run_cli("--wal-dir", self.fixture.directory)


@unittest.skipUnless(
    (PG_BIN / "initdb").is_file() and os.geteuid() != 0,
    "real PostgreSQL WAL tests require matching initdb and a non-root container user",
)
class RealPostgresTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="wal-audit-pg-")
        cls.root = Path(cls.temp.name)
        cls.data = cls.root / "data"
        cls.socket = cls.root / "socket"
        cls.socket.mkdir()
        cls.port = "55432"
        cls.running = False
        try:
            cls.command("initdb", "-D", cls.data, "-U", "postgres",
                        "-A", "trust", "--no-locale", "--wal-segsize=1")
            options = (
                f"-c unix_socket_directories={cls.socket} -c listen_addresses='' "
                f"-c port={cls.port} -c fsync=off -c wal_level=logical "
                "-c max_prepared_transactions=10"
            )
            cls.command("pg_ctl", "-D", cls.data, "-l", cls.root / "server.log",
                        "-o", options, "-w", "start")
            cls.running = True
            cls.sql(
                "CREATE TABLE audit_fixture (shard_key_value bigint NOT NULL, "
                "object_id bytea NOT NULL, document bytea NOT NULL);"
            )
            cls.identity = cls.sql(
                "SELECT system_identifier FROM pg_control_system();"
            )
            cls.database_oid = int(cls.sql(
                "SELECT oid FROM pg_database WHERE datname = current_database();"
            ))
            cls.relfilenode = int(cls.sql(
                "SELECT pg_relation_filenode('audit_fixture');"
            ))
            cls.start = cls.sql("SELECT pg_current_wal_insert_lsn();")
            cls.segment_name = cls.sql(f"SELECT pg_walfile_name('{cls.start}');")
            object_hex = bson_ints(**{"": 123}).hex()
            document_hex = bson_ints(_id=123, value=456).hex()
            insert = (
                "INSERT INTO audit_fixture VALUES "
                f"(0, decode('{object_hex}', 'hex'), decode('{document_hex}', 'hex'));"
            )
            cls.sql("BEGIN;" + insert + "COMMIT;")
            cls.sql("BEGIN;" + insert + "ROLLBACK;")
            prepared_object = bson_ints(**{"": 223}).hex()
            prepared_document = bson_ints(_id=223, value=556).hex()
            cls.sql(
                "BEGIN; INSERT INTO audit_fixture VALUES "
                f"(0, decode('{prepared_object}', 'hex'), "
                f"decode('{prepared_document}', 'hex')); "
                "PREPARE TRANSACTION 'wal_audit_fixture';"
            )
            cls.sql("COMMIT PREPARED 'wal_audit_fixture';")
            cls.sql(
                "BEGIN; SAVEPOINT child;" + insert
                + "ROLLBACK TO SAVEPOINT child; COMMIT;"
            )
            cls.sql(
                "UPDATE audit_fixture SET document = decode('"
                + bson_ints(_id=123, value=789).hex()
                + "', 'hex') WHERE object_id = decode('" + object_hex + "', 'hex');"
            )
            cls.sql("DELETE FROM audit_fixture WHERE object_id = decode('"
                    + object_hex + "', 'hex');")
            cls.sql("SELECT pg_switch_wal();")
            cls.archive = cls.root / "archive"
            cls.archive.mkdir()
            shutil.copyfile(cls.data / "pg_wal" / cls.segment_name, cls.archive / cls.segment_name)
            cls.manifest = cls.root / "manifest.json"
            cls.manifest.write_text(json.dumps({
                "schemaVersion": 1, "postgresMajor": PG_MAJOR,
                "systemIdentifier": cls.identity, "timeline": 1,
                "documentdbVersion": "ordinary-bson-v1",
                "validFromLsn": cls.start, "validToLsn": "FFFFFFFF/FFFFFFFF",
                "relations": [{
                    "tblspaceOid": 1663, "databaseOid": cls.database_oid,
                    "relfilenode": cls.relfilenode, "collectionId": 123,
                    "database": "test", "collection": "fixture",
                }],
            }))
        except BaseException:
            cls.tearDownClass()
            raise

    @classmethod
    def tearDownClass(cls):
        if getattr(cls, "running", False):
            cls.command("pg_ctl", "-D", cls.data, "-m", "immediate", "-w", "stop")
            cls.running = False
        if hasattr(cls, "temp"):
            cls.temp.cleanup()

    @classmethod
    def command(cls, program, *args):
        result = subprocess.run(
            [str(PG_BIN / program), *map(str, args)],
            text=True, capture_output=True, timeout=60,
        )
        if result.returncode:
            raise RuntimeError(f"{program} failed: {result.stderr}\n{result.stdout}")
        return result.stdout.strip()

    @classmethod
    def sql(cls, statement):
        return cls.command(
            "psql", "-X", "-q", "-t", "-A", "-v", "ON_ERROR_STOP=1",
            "-h", cls.socket, "-p", cls.port, "-U", "postgres",
            "-d", "postgres", "-c", statement,
        )

    def test_native_wal_committed_insert_and_abort(self):
        result = subprocess.run(
            [str(BINARY), "--wal-dir", str(self.archive), "--manifest", str(self.manifest),
             "--from-lsn", self.start, "--format", "jsonl"],
            text=True, capture_output=True, timeout=60,
        )
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        events = [json.loads(line) for line in result.stdout.splitlines() if line]
        inserts = [e for e in events if e.get("operation") == "insert"]
        self.assertEqual(len(inserts), 2)
        self.assertEqual(inserts[0]["collection"], "fixture")
        # FPI-only records can legitimately lack separately logged tuple bytes.
        if inserts[0]["after"] is not None:
            self.assertEqual(inserts[0]["after"]["value"], {"$numberInt": "456"})
        self.assertIsNotNone(inserts[0]["commitLsn"])
        self.assertTrue(any(e.get("operation") == "update" for e in events))
        self.assertTrue(any(e.get("operation") == "delete" for e in events))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--binary", type=Path, default=BINARY)
    parser.add_argument("--pg-major", type=int, choices=(16, 17, 18), default=PG_MAJOR)
    options, remaining = parser.parse_known_args()
    BINARY = options.binary.resolve()
    PG_MAJOR = options.pg_major
    unittest.main(argv=[__file__, *remaining])
