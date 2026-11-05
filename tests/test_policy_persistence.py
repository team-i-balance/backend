"""Restart, multi-process transactions, and persistent signing-identity checks."""
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict

import pytest


def payload(version=1):
    return {
        "schema": 1, "org": "acme", "version": version,
        "expires_at": "2999-01-01T00:00:00+00:00",
        "rules": [{"id": "r1", "label": "고객 ID"}],
        "types": {"전화번호": {"on": False}},
        "thresholds": {"personal": 0.35},
    }


MODEL = {"name": "pii-slm", "version": "0.3.0", "sha256": "abc", "url": "https://example.test/model"}


def run_python(code, **extra_env):
    result = subprocess.run(
        [sys.executable, "-c", code], env={**os.environ, **extra_env},
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def publish(client):
    response = client.post("/policy/publish", json={"payload": payload()})
    assert response.status_code == 200
    return response.json()


def snapshot(store):
    return {
        "history": [asdict(b) for b in store.history()],
        "active": asdict(store.current()) if store.current() else None,
        "acks": store.ack_summary(), "v1": store.ack_summary(1),
        "model": store.model_manifest(), "next": store.next_version(),
    }


def test_fresh_server_process_restores_all_policy_apis_and_continues_versions(client):
    from app.policy import PRIV_KEY_PATH

    publish(client)
    publish(client)
    latest = client.get("/policy/latest")
    assert client.post("/policy/deploy", json={"bundle": latest.json()}).json()["accepted"]
    for device, version, status, reason in [
        ("a", 1, "applied", None), ("a", 2, "rejected", "expired"),
        ("b", 2, "applied", None), ("a", 1, "rejected", "rollback"),
    ]:
        assert client.post("/policy/ack", json={
            "device_id": device, "version": version, "status": status, "reason": reason,
        }).status_code == 200
    assert client.post("/policy/model/publish", json=MODEL).status_code == 200
    routes = ["/policy/history", "/policy/latest", "/policy/current", "/policy/1", "/policy/2",
              "/policy/acks", "/policy/1/acks", "/policy/2/acks", "/policy/model/latest"]
    expected = {path: client.get(path).json() for path in routes}
    key_digest = hashlib.sha256(PRIV_KEY_PATH.read_bytes()).hexdigest()
    # Real fresh interpreter and FastAPI lifespan, sharing only DB/key files.
    actual = run_python("""
import hashlib, json, os
from fastapi.testclient import TestClient
from main import app
from app.policy import PRIV_KEY_PATH
with TestClient(app) as c:
    before = {path: c.get(path).json() for path in json.loads(os.environ['TEST_ROUTES'])}
    latest = c.get('/policy/latest')
    cached = c.get('/policy/latest', headers={'If-None-Match': latest.headers['etag']})
    old = c.post('/policy/deploy', json={'bundle': c.get('/policy/1').json()}).json()
    processed = c.post('/process', json={'text': '연락 010-1234-5678', 'rules_only': True}).json()
    published = c.post('/policy/publish', json={'payload': json.loads(os.environ['TEST_PAYLOAD'])}).json()
    print(json.dumps({'before': before, 'etag': latest.headers['etag'], 'cached': cached.status_code,
        'rollback': old, 'processed': processed, 'published': published,
        'key': hashlib.sha256(PRIV_KEY_PATH.read_bytes()).hexdigest()}))
""", TEST_ROUTES=json.dumps(routes), TEST_PAYLOAD=json.dumps(payload()))
    assert actual["before"] == expected
    assert actual["etag"] == latest.headers["etag"] and actual["cached"] == 304
    assert actual["rollback"]["accepted"] is False
    assert actual["rollback"]["reason"] == "rollback"
    assert actual["rollback"]["policy"]["version"] == 2
    assert "PHONE" not in actual["processed"]["detected_types"]
    assert actual["published"]["version"] == 3
    assert actual["key"] == key_digest
    # The original worker must see the second worker's committed publication.
    assert client.get("/policy/history").json()[0]["version"] == 3


def test_independent_stores_observe_new_state_and_reject_rollback(client, tmp_path):
    from app.policy import PolicyStore, make_bundle

    path = tmp_path / "shared.db"
    first, second = PolicyStore(db_path=path), PolicyStore(db_path=path)
    assert first.current() is None
    assert second.deploy(make_bundle(payload(7)))[0]
    assert first.current().version == 7
    assert not first.deploy(make_bundle(payload(6)))[0]
    # Publishing cannot restart below a restored externally deployed policy.
    assert first.next_version() == 8
    assert first.publish(payload()).version == 8
    assert second.latest().version == 8
    assert second.next_version() == 9


def test_multiple_processes_publish_unique_contiguous_versions(client):
    script = """
import json, os
from app.policy import PolicyStore
s = PolicyStore(db_path=os.environ['POLICY_DB_PATH'])
versions = [s.publish({'schema': 1, 'org': 'acme', 'rules': []}).version for _ in range(3)]
print(json.dumps(versions))
"""
    with ThreadPoolExecutor(max_workers=4) as pool:
        groups = list(pool.map(lambda _: run_python(script), range(4)))
    assert sorted(v for group in groups for v in group) == list(range(1, 13))
    history = client.get("/policy/history").json()
    assert [row["version"] for row in history] == list(range(12, 0, -1))
    from app.policy import DsseVerifier, bundle_hash
    for version in range(1, 13):
        envelope = client.get(f"/policy/{version}").json()
        assert DsseVerifier().verify(envelope, last_version=None).version == version
        assert bundle_hash(envelope) == history[12 - version]["sha256"]


def test_first_key_creation_is_shared_across_processes_with_different_databases(client, tmp_path):
    script = """
import json, os
from app.policy import PolicyStore
s = PolicyStore(db_path=os.environ['TEST_DB'])
print(json.dumps(s.publish({'schema': 1, 'org': 'acme', 'rules': []}).envelope))
"""
    with ThreadPoolExecutor(max_workers=4) as pool:
        bundles = list(pool.map(lambda i: run_python(script, TEST_DB=str(tmp_path / f"worker-{i}.db")), range(4)))
    from app.policy import DsseVerifier, PRIV_KEY_PATH
    for bundle in bundles:
        assert DsseVerifier().verify(bundle, last_version=None).version == 1
    assert PRIV_KEY_PATH.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize("table", ["policy_bundle", "policy_active", "policy_ack", "model_manifest"])
def test_write_failure_rolls_back_without_mutating_read_state(client, table):
    from app.policy import store

    stored = store.publish(payload())
    assert store.deploy(stored.envelope)[0]
    store.record_ack("pc", 1, "applied", None)
    store.publish_model(MODEL)
    before = snapshot(store)
    with sqlite3.connect(os.environ["POLICY_DB_PATH"]) as conn:
        conn.execute(f"""CREATE TRIGGER reject_write BEFORE INSERT ON {table}
            BEGIN SELECT RAISE(ABORT, 'simulated storage failure'); END""")
    from app.policy import make_bundle
    actions = {
        "policy_bundle": lambda: store.publish(payload()),
        "policy_active": lambda: store.deploy(make_bundle(payload(2))),
        "policy_ack": lambda: store.record_ack("pc", 1, "rejected", "expired"),
        "model_manifest": lambda: store.publish_model({**MODEL, "version": "0.4.0"}),
    }
    with pytest.raises(sqlite3.IntegrityError, match="simulated storage failure"):
        actions[table]()
    assert snapshot(store) == before


def test_signer_failure_does_not_reserve_or_skip_version(client):
    from app.policy import store

    publish(client)
    def fail(_):
        raise RuntimeError("signer unavailable")
    with pytest.raises(RuntimeError, match="signer unavailable"):
        store.publish(payload(), signer=fail)
    assert store.next_version() == 2
    assert publish(client)["version"] == 2


def test_ack_timestamps_and_all_reports_persist_with_latest_per_device_semantics(client):
    from app.policy import PolicyStore, store

    store.record_ack("pc", 2, "applied", None)
    store.record_ack("pc", 1, "rejected", "rollback")
    store.record_ack("pc", 1, "applied", None)
    store.record_ack("other", 1, "rejected", "expired")
    with sqlite3.connect(os.environ["POLICY_DB_PATH"]) as conn:
        rows = conn.execute("SELECT device_id, version, status, reason, at FROM policy_ack ORDER BY id").fetchall()
    assert len(rows) == 4 and all(row[4] for row in rows)
    restored = PolicyStore(db_path=os.environ["POLICY_DB_PATH"])
    assert restored.ack_summary() == {"devices": 2, "applied": 1, "rejected": 1, "reject_reasons": {"expired": 1}}
    assert restored.ack_summary(2) == {"devices": 1, "applied": 1, "rejected": 0, "reject_reasons": {}}
    assert restored.ack_summary(1) == store.ack_summary(1)


@pytest.mark.parametrize("damage", ["private_missing", "both_missing", "private_invalid", "public_mismatch", "both_replaced"])
@pytest.mark.parametrize("endpoint", ["/policy/publish", "/policy/model/publish"])
def test_lost_or_changed_key_fails_closed_and_preserves_stored_state(client, damage, endpoint):
    from app.policy import PRIV_KEY_PATH, TRUST_DIR, DEMO_KEY_ID, store
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    publish(client)
    store.publish_model(MODEL)
    before = snapshot(store)
    public = TRUST_DIR / f"{DEMO_KEY_ID}.pub"
    if damage in ("private_missing", "both_missing"):
        PRIV_KEY_PATH.unlink()
        if damage == "both_missing":
            public.unlink()
    elif damage == "private_invalid":
        PRIV_KEY_PATH.write_bytes(b"not a private key")
    else:
        different = Ed25519PrivateKey.generate()
        public.write_bytes(different.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
        ))
        if damage == "both_replaced":
            PRIV_KEY_PATH.write_bytes(different.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption(),
            ))
    body = {"payload": payload()} if endpoint == "/policy/publish" else MODEL
    response = client.post(endpoint, json=body)
    assert response.status_code == 503
    assert snapshot(store) == before
    if damage in ("private_missing", "both_missing"):
        assert not PRIV_KEY_PATH.exists()  # Must not silently create a new identity.


def test_model_only_store_also_remembers_signing_identity(client):
    from app.policy import PRIV_KEY_PATH, TRUST_DIR, DEMO_KEY_ID

    assert client.post("/policy/model/publish", json=MODEL).status_code == 200
    PRIV_KEY_PATH.unlink()
    (TRUST_DIR / f"{DEMO_KEY_ID}.pub").unlink()
    assert client.post("/policy/publish", json={"payload": payload()}).status_code == 503


def test_missing_public_key_is_recovered_without_rotating_private_key(client):
    from app.policy import PRIV_KEY_PATH, TRUST_DIR, DEMO_KEY_ID, DsseVerifier

    publish(client)
    original_private = PRIV_KEY_PATH.read_bytes()
    public = TRUST_DIR / f"{DEMO_KEY_ID}.pub"
    original_public = public.read_bytes()
    public.unlink()
    assert publish(client)["version"] == 2
    assert PRIV_KEY_PATH.read_bytes() == original_private and public.read_bytes() == original_public
    assert DsseVerifier().verify(client.get("/policy/latest").json(), last_version=1).version == 2


def test_equivalent_public_key_pem_is_not_replaced(client):
    from app.policy import TRUST_DIR, DEMO_KEY_ID

    publish(client)
    public = TRUST_DIR / f"{DEMO_KEY_ID}.pub"
    equivalent = public.read_bytes().replace(b"\n", b"\r\n")
    public.write_bytes(equivalent)
    assert publish(client)["version"] == 2
    assert public.read_bytes() == equivalent


def test_existing_unpinned_key_files_are_reused_on_first_persistent_publish(client):
    from app.policy import make_bundle, PRIV_KEY_PATH, TRUST_DIR, DEMO_KEY_ID, DsseVerifier

    old = make_bundle(payload(4))  # A key generated before persistent state existed.
    key = PRIV_KEY_PATH.read_bytes()
    public = (TRUST_DIR / f"{DEMO_KEY_ID}.pub").read_bytes()
    assert client.post("/policy/deploy", json={"bundle": old}).json()["accepted"]
    assert publish(client)["version"] == 5
    assert PRIV_KEY_PATH.read_bytes() == key
    assert (TRUST_DIR / f"{DEMO_KEY_ID}.pub").read_bytes() == public
    assert DsseVerifier().verify(client.get("/policy/latest").json(), last_version=4).version == 5


def test_existing_database_other_tables_are_preserved(client, tmp_path):
    from app.policy import PolicyStore

    path = tmp_path / "existing.db"
    with sqlite3.connect(path) as conn:
        conn.execute("CREATE TABLE unrelated_log (value TEXT)")
        conn.execute("INSERT INTO unrelated_log VALUES ('keep me')")
    store = PolicyStore(db_path=path)
    store.initialize()
    store.publish(payload())
    PolicyStore(db_path=path).initialize()
    with sqlite3.connect(path) as conn:
        assert conn.execute("SELECT value FROM unrelated_log").fetchone()[0] == "keep me"
    assert PolicyStore(db_path=path).next_version() == 2


def test_corrupt_database_is_not_silently_replaced_or_reset(client, tmp_path):
    from app.policy import PolicyStore

    path = tmp_path / "broken.db"
    path.write_bytes(b"broken policy database")
    with pytest.raises(sqlite3.DatabaseError):
        PolicyStore(db_path=path).initialize()
    assert path.read_bytes() == b"broken policy database"


def test_returned_objects_cannot_mutate_persisted_policy_state(client):
    from app.policy import store

    stored = store.publish(payload())
    store.deploy(stored.envelope)
    store.publish_model(MODEL)
    before = snapshot(store)
    store.current().types.clear()
    store.latest().envelope.clear()
    store.model_manifest().clear()
    assert snapshot(store) == before


def test_persistent_reset_is_refused(client):
    from app.policy import store

    publish(client)
    before = snapshot(store)
    with pytest.raises(RuntimeError, match="in-memory test stores"):
        store.reset()
    assert snapshot(store) == before


def test_process_exit_during_write_does_not_consume_next_version(client):
    publish(client)
    assert run_python("""
import json, os, sqlite3
conn = sqlite3.connect(os.environ['POLICY_DB_PATH'])
conn.execute('BEGIN IMMEDIATE')
conn.execute("INSERT INTO policy_bundle (version, envelope, sha256) VALUES (2, '{}', 'incomplete')")
print(json.dumps(True), flush=True)
os._exit(0)  # no commit / connection close: exercise SQLite journal recovery
""") is True
    assert [item["version"] for item in client.get("/policy/history").json()] == [1]
    assert publish(client)["version"] == 2
