"""Encrypted export tests (app/crypto.py and /logs/export)."""
import base64
import json
from pathlib import Path

import pytest


def _event(**kw):
    base = {"grade": "sensitive_S", "action": "send_transformed",
            "detected_types": ["rrn"], "detected_count": 2}
    base.update(kw)
    return base


def test_export_roundtrip(client):
    for i in range(3):
        client.post("/logs/events", json=_event(request_id=f"r{i}"))

    r = client.post("/logs/export")
    assert r.status_code == 200
    body = r.json()
    assert body["exported"] == 3
    assert body["public_key_fingerprint"]

    # Decrypt with the temp private key and confirm fidelity.
    from app.crypto import decrypt_file

    recs = decrypt_file(Path(body["file"]))
    assert len(recs) == 3
    assert {rec["request_id"] for rec in recs} == {"r0", "r1", "r2"}
    assert all(rec["detected_types"] == ["rrn"] for rec in recs)


def test_export_filters_by_queue(client):
    client.post("/logs/events", json=_event(reason="false_positive"))  # detection_improve
    client.post("/logs/events", json=_event())  # pre_warning
    r = client.post("/logs/export", params={"queue": "detection_improve"})
    assert r.json()["exported"] == 1


def test_export_empty(client):
    r = client.post("/logs/export")
    assert r.status_code == 200
    assert r.json()["exported"] == 0
    from app.crypto import decrypt_file
    assert decrypt_file(Path(r.json()["file"])) == []


def test_envelope_has_no_plaintext(client):
    client.post("/logs/events", json=_event(request_id="secret-req-id"))
    r = client.post("/logs/export")
    raw = Path(r.json()["file"]).read_text()
    # The request_id must not appear in cleartext anywhere in the file.
    assert "secret-req-id" not in raw
    env = json.loads(raw)
    assert env["scheme"] == "RSA-OAEP-SHA256 + AES-256-GCM"
    assert set(env) >= {"enc_key", "nonce", "ciphertext", "record_count"}


def test_tampered_ciphertext_fails_to_decrypt(client):
    client.post("/logs/events", json=_event())
    r = client.post("/logs/export")
    path = Path(r.json()["file"])
    env = json.loads(path.read_text())

    # Flip a byte in the ciphertext -> AES-GCM auth must reject it.
    ct = bytearray(base64.b64decode(env["ciphertext"]))
    ct[0] ^= 0x01
    env["ciphertext"] = base64.b64encode(bytes(ct)).decode()
    path.write_text(json.dumps(env))

    from app.crypto import decrypt_file

    with pytest.raises(Exception):
        decrypt_file(path)


def test_public_key_reused_across_exports(client):
    client.post("/logs/events", json=_event())
    fp1 = client.post("/logs/export").json()["public_key_fingerprint"]
    fp2 = client.post("/logs/export").json()["public_key_fingerprint"]
    assert fp1 == fp2  # key generated once, then stable


def test_concurrent_exports_get_unique_files(client):
    # Regression (P2-2): two exports in quick succession (same second) must
    # not overwrite each other. Different queue filters must each keep their
    # own artifact with the correct contents.
    client.post("/logs/events", json=_event(reason="false_positive"))  # detection_improve
    client.post("/logs/events", json=_event())  # pre_warning

    r1 = client.post("/logs/export", params={"queue": "detection_improve"}).json()
    r2 = client.post("/logs/export", params={"queue": "pre_warning"}).json()

    assert r1["file"] != r2["file"], "exports must use distinct file paths"
    assert r1["exported"] == 1
    assert r2["exported"] == 1

    from app.crypto import decrypt_file

    # Each file must still contain exactly what its call reported.
    recs1 = decrypt_file(Path(r1["file"]))
    recs2 = decrypt_file(Path(r2["file"]))
    assert len(recs1) == 1 and recs1[0]["queue"] == "detection_improve"
    assert len(recs2) == 1 and recs2[0]["queue"] == "pre_warning"


def test_many_rapid_exports_all_distinct(client):
    client.post("/logs/events", json=_event())
    paths = {client.post("/logs/export").json()["file"] for _ in range(10)}
    assert len(paths) == 10  # all unique, none overwritten


def test_export_retries_on_filename_collision(client, monkeypatch):
    # Force the exclusive-create ('x' mode) to collide once, exercising the
    # retry branch, then succeed on the next token.
    import builtins

    import app.crypto as crypto

    real_open = builtins.open
    calls = {"x": 0}

    def flaky_open(file, mode="r", *args, **kwargs):
        if mode == "x":
            calls["x"] += 1
            if calls["x"] == 1:
                raise FileExistsError(file)
        return real_open(file, mode, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", flaky_open)

    out = crypto.encrypt_records([{"queue": "pre_warning"}])
    assert calls["x"] == 2  # first collided, second succeeded
    assert out.exists()
    assert crypto.decrypt_file(out) == [{"queue": "pre_warning"}]
