"""Real Mongo protocol workload and independent canonical BSON WAL oracle."""

import collections
import datetime
import json
import os
from pathlib import Path
import sys
import time

from bson import Binary, Decimal128, Int64, ObjectId, json_util
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure


ROOT = Path("/artifacts")
DATABASE = "wal_audit_mongo"
OPTIONS = json_util.CANONICAL_JSON_OPTIONS


def canonical(value):
    return json.loads(json_util.dumps(value, json_options=OPTIONS))


def save(name, value):
    (ROOT / name).write_text(json.dumps(value, indent=2) + "\n")


def client():
    connection = MongoClient(
        "documentdb", 10260, username=os.environ["MONGO_USERNAME"],
        password=os.environ["MONGO_PASSWORD"], tls=True,
        tlsAllowInvalidCertificates=True, retryWrites=False,
        serverSelectionTimeoutMS=3000, tz_aware=True,
    )
    last_error = None
    for _ in range(90):
        try:
            connection.admin.command("ping")
            return connection
        except ConnectionFailure as error:
            last_error = error
            time.sleep(2)
    connection.close()
    detail = f"{type(last_error).__name__}: {last_error}"
    for key in ("MONGO_USERNAME", "MONGO_PASSWORD"):
        if os.environ.get(key):
            detail = detail.replace(os.environ[key], "<redacted>")
    raise AssertionError(f"public Mongo gateway did not become ready: {detail}") from None


def workload(phase):
    with client() as connection:
        db = connection[DATABASE]
        if phase == "create":
            db.create_collection("items")
            assert "items" in db.list_collection_names()
            assert db.items.count_documents({}) == 0
            return
        if phase == "rename":
            old = list(db.items.find().sort("_id", 1))
            db.items.rename("renamed")
            assert "items" not in db.list_collection_names()
            assert "renamed" in db.list_collection_names()
            assert canonical(old) == canonical(list(db.renamed.find().sort("_id", 1)))
            return
        if phase == "drop":
            db.drop_collection("renamed")
            assert "renamed" not in db.list_collection_names()
            connection.drop_database(DATABASE)
            assert DATABASE not in connection.list_database_names()
            return

        collection = db["items" if phase == "original" else "renamed"]
        expected = []

        def effect(operation, identifier, before, after):
            expected.append({
                "operation": operation, "objectId": canonical({"_id": identifier}),
                "before": canonical(before), "after": canonical(after),
            })

        def insert(document):
            result = collection.insert_one(document)
            assert result.acknowledged and result.inserted_id == document["_id"]
            actual = collection.find_one({"_id": document["_id"]})
            assert canonical(actual) == canonical(document)
            effect("insert", document["_id"], None, actual)

        if phase == "original":
            insert({
                "_id": ObjectId("0123456789abcdef01234567"),
                "marker": "mongo-wal-value-ONE", "count": 1,
                "long": Int64(2**40), "decimal": Decimal128("12.50"),
                "binary": Binary(b"\x00\x01\xfe"), "flag": True,
                "nested": {"empty": None, "array": [1, "two", False]},
                "when": datetime.datetime(2025, 1, 2, 3, 4, 5, tzinfo=datetime.timezone.utc),
            })
            documents = [
                {"_id": ObjectId("1123456789abcdef01234567"), "marker": "mongo-wal-value-TWO", "count": 2},
                {"_id": ObjectId("2123456789abcdef01234567"), "marker": "mongo-wal-value-THREE", "count": 3},
            ]
            result = collection.insert_many(documents, ordered=True)
            assert result.acknowledged and result.inserted_ids == [d["_id"] for d in documents]
            for document in documents:
                actual = collection.find_one({"_id": document["_id"]})
                assert canonical(actual) == canonical(document)
                effect("insert", document["_id"], None, actual)
            assert collection.count_documents({}) == 3
            index = collection.create_index("marker", name="marker_e2e")
            assert index == "marker_e2e" and index in collection.index_information()
            collection.drop_index(index)
            assert index not in collection.index_information()
            identifier = documents[0]["_id"]
            before = collection.find_one({"_id": identifier})
            result = collection.update_one({"_id": identifier}, {"$set": {"marker": "mongo-wal-value-UPDATED", "count": 22}})
            assert result.acknowledged and result.matched_count == result.modified_count == 1
            after = collection.find_one({"_id": identifier})
            assert after == {**before, "marker": "mongo-wal-value-UPDATED", "count": 22}
            effect("update", identifier, before, after)
            identifier = documents[1]["_id"]
            before = collection.find_one({"_id": identifier})
            replacement = {"_id": identifier, "marker": "mongo-wal-value-REPLACED", "count": 33}
            result = collection.replace_one({"_id": identifier}, replacement)
            assert result.acknowledged and result.matched_count == result.modified_count == 1
            after = collection.find_one({"_id": identifier})
            assert after == replacement
            effect("update", identifier, before, after)
        elif phase == "renamed":
            insert({"_id": ObjectId("3123456789abcdef01234567"), "marker": "mongo-wal-value-RENAMED", "count": 4})
            identifier = ObjectId("1123456789abcdef01234567")
            before = collection.find_one({"_id": identifier})
            assert before["count"] == 22
            result = collection.delete_one({"_id": identifier})
            assert result.acknowledged and result.deleted_count == 1
            assert collection.find_one({"_id": identifier}) is None
            effect("delete", identifier, before, None)
            assert collection.count_documents({}) == 3
        else:
            raise AssertionError(f"unknown workload phase {phase}")
        save(f"{phase}.expected.json", expected)
        save(f"{phase}.mongo-state.json", canonical(list(collection.find().sort("_id", 1))))


def number(lsn):
    high, low = lsn.split("/")
    return (int(high, 16) << 32) + int(low, 16)


def verify():
    mode = (ROOT / "mode.txt").read_text().strip()
    catalog_relations = json.loads((ROOT / "catalog-relations.json").read_text())

    def catalog_records(events):
        return [
            e for e in events if e["eventType"] == "postgresRecord"
            and any(
                all(block[key] == relation[key] for key in ("tblspaceOid", "databaseOid", "relfilenode"))
                for block in e.get("blocks", []) for relation in catalog_relations
            )
        ]

    physical_summary = []
    for phase in ("original", "renamed"):
        expected = json.loads((ROOT / f"{phase}.expected.json").read_text())
        events = [json.loads(line) for line in (ROOT / f"{phase}.jsonl").read_text().splitlines()]
        documents = [e for e in events if e["eventType"] == "document"]
        physical_summary.append({
            "mode": mode, "phase": phase, "mongoExpected": len(expected),
            "physicalEffects": len(documents),
            "completeEffects": sum(e["certainty"] == "certain" for e in documents),
            "operations": dict(collections.Counter(e["operation"] for e in documents)),
            "warnings": sorted({warning for e in documents for warning in e["warnings"]}),
        })
    save("physical-summary.json", physical_summary)
    summary = []
    for phase in ("original", "renamed"):
        expected = json.loads((ROOT / f"{phase}.expected.json").read_text())
        manifest = json.loads((ROOT / f"{phase}.manifest.json").read_text())
        events = [json.loads(line) for line in (ROOT / f"{phase}.jsonl").read_text().splitlines()]
        assert not any(e["eventType"] == "error" for e in events)
        documents = [e for e in events if e["eventType"] == "document"]
        assert len(documents) == len(expected), (phase, documents, expected)
        if phase == "original":
            assert catalog_records(events), "index lifecycle must expose physical catalog WAL"
        for actual, wanted in zip(documents, expected):
            assert actual["outcome"] == "committed", actual
            assert actual["database"] == DATABASE, actual
            assert actual["collection"] == ("items" if phase == "original" else "renamed"), actual
            if mode == "precision":
                assert actual["certainty"] == "certain" and actual["warnings"] == [], actual
            elif actual["certainty"] == "incomplete":
                supported_gaps = {
                    "tuple bytes are unavailable (including full-page-image-only records)",
                    "before document is unavailable in physical WAL",
                    "after document is unavailable in physical WAL",
                    "before document is unavailable; only replica-identity key is logged",
                    "multi-insert tuple bytes unavailable (full-page image is not extracted)",
                }
                assert actual["warnings"] and set(actual["warnings"]) <= supported_gaps, actual
                assert any(actual[key] is None for key in ("before", "after") if wanted[key] is not None), actual
            else:
                assert actual["certainty"] == "certain" and actual["warnings"] == [], actual
            assert number(manifest["validFromLsn"]) <= number(actual["eventLsn"]) < number(manifest["validToLsn"])
            assert number(actual["eventLsn"]) < number(actual["commitLsn"])
            for key in ("operation", "objectId", "before", "after"):
                if mode == "default" and key != "operation" and actual[key] is None and wanted[key] is not None:
                    assert actual["certainty"] == "incomplete" and actual["warnings"], actual
                    continue
                assert actual[key] == wanted[key], (phase, key, actual, wanted)
        groups = collections.defaultdict(list)
        for event in documents:
            groups[event["transactionId"]].append(number(event["eventLsn"]))
        assert all(values == sorted(values) for values in groups.values())
        summaries = {e["transactionId"]: e for e in events if e["eventType"] == "transaction"}
        assert all(summaries[xid]["outcome"] == "committed" for xid in groups)
        redacted_text = (ROOT / f"{phase}.redacted.jsonl").read_text()
        redacted = [json.loads(line) for line in redacted_text.splitlines()]
        assert len(redacted) == len(events)
        for event in redacted:
            assert all(event.get(key) is None for key in ("objectId", "before", "after"))
        assert "mongo-wal-value" not in redacted_text
        assert "0123456789abcdef01234567" not in redacted_text
        assert [(e["eventType"], e["eventLsn"], e.get("collection"), e.get("outcome")) for e in events] == [
            (e["eventType"], e["eventLsn"], e.get("collection"), e.get("outcome")) for e in redacted
        ]
        counts = collections.Counter(e["operation"] for e in documents)
        incomplete = sum(e["certainty"] == "incomplete" for e in documents)
        summary.append({"mode": mode, "phase": phase, "expected": len(expected), "decoded": len(documents), "incomplete": incomplete, "operations": dict(counts)})
        if mode == "default":
            assert any(e["operation"] in ("update", "delete") and e["certainty"] == "incomplete" for e in documents), documents
    for phase in ("create", "rename", "drop"):
        events = [json.loads(line) for line in (ROOT / f"{phase}.jsonl").read_text().splitlines()]
        assert catalog_records(events), (phase, "missing physical catalog WAL")
        assert not any(e["eventType"] == "document" for e in events), phase
    save("summary.json", summary)
    print(json.dumps(summary, indent=2))
    print(f"PASS ({mode}): acknowledged Mongo writes, read-back, all available canonical BSON values, IDs, namespaces, commit order, and redaction.")
    print("DDL scope: lifecycle verified through Mongo; WAL reports physical PostgreSQL records, NOT decoded DDL commands.")


if __name__ == "__main__":
    if sys.argv[1] == "verify":
        verify()
    elif sys.argv[1] == "extract":
        for path in (ROOT / "wal").glob("*.hex"):
            path.with_suffix("").write_bytes(bytes.fromhex(path.read_text().strip()))
            path.unlink()
    else:
        workload(sys.argv[1])
