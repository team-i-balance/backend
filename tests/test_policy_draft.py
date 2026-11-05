"""Durable console drafts, optimistic concurrency, and atomic publication."""
import base64
import json
import os
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from threading import Barrier

import pytest

from tests.test_policy_persistence import MODEL, run_python


def payload():
    return {
        "schema": 1, "org": "acme", "thresholds": {"personal": 0.35},
        "rules": [{"id": "r-1", "label": "주민등록번호", "description": "번호가 포함된 입력",
                   "grade": "S", "action": "태그"}],
        "types": {"이름": {"on": False, "grade": "S", "method": "가명"}},
        "dict": [{"h": "a" * 64, "type": "회사 고유 단어"}],
        "exclude": [{"h": "b" * 64}],
    }


def draft(client):
    response = client.get("/policy/draft")
    assert response.status_code == 200
    assert response.headers["etag"] == response.json()["etag"]
    assert response.headers["cache-control"] == "no-store"
    return response.json()


def save(client, state=None, **overrides):
    state = state or draft(client)
    body = {"payload": payload(), "changes": [{"what": "자동 변환 추가", "src": "INC-42"}]}
    body.update(overrides)
    response = client.put("/policy/draft", json=body, headers={"If-Match": state["etag"]})
    assert response.status_code == 200, response.text
    assert response.headers["etag"] == response.json()["etag"]
    assert response.headers["cache-control"] == "no-store"
    return response.json()


def decode(envelope):
    return json.loads(base64.b64decode(envelope["payload"], validate=True))


def test_empty_draft_and_latest_published_fallback(client):
    empty = draft(client)
    assert empty["payload"] is None
    assert empty["changes"] == [] and empty["has_draft"] is False
    assert empty["base_version"] is None and empty["revision"] == 0
    assert empty["updated_at"] is None and empty["updated_by"] is None
    assert empty["etag"].startswith('"sha256:') and empty["etag"].endswith('"')
    assert draft(client) == empty

    assert client.post("/policy/publish", json={"payload": payload()}).status_code == 200
    latest = draft(client)
    assert latest["payload"] == {**payload(), "version": 1}
    assert latest["payload"] == decode(client.get("/policy/latest").json())
    assert latest["has_draft"] is False and latest["changes"] == []
    assert latest["base_version"] == 1 and latest["etag"] != empty["etag"]
    assert client.get("/policy/current").json()["active"] is False
    # A publication also invalidates an editor who loaded the empty fallback.
    response = client.put("/policy/draft", json={"payload": {}, "changes": []},
                          headers={"If-Match": empty["etag"]})
    assert response.status_code == 409


def test_save_preserves_all_policy_fields_without_publishing_or_activating(client):
    original = draft(client)
    state = save(client, original)
    assert state["payload"] == payload()
    assert state["has_draft"] is True and state["revision"] == 1
    assert state["base_version"] is None and state["etag"] != original["etag"]
    assert state == draft(client)
    assert state["changes"][0]["src"] == "INC-42"
    assert client.get("/policy/latest").status_code == 404
    assert client.get("/policy/history").json() == []
    assert client.get("/policy/current").json()["active"] is False
    # This is a full snapshot, including deletions, not an append/merge endpoint.
    replaced = save(client, state, payload={"schema": 1, "rules": []}, changes=[])
    assert replaced["payload"] == {"schema": 1, "rules": []}
    assert replaced["changes"] == [] and replaced["revision"] == 2


def test_metadata_is_server_owned_and_survives_other_editors(client):
    from app.policy_router import get_policy_editor

    start = datetime.now(timezone.utc)
    saved = save(client, changes=[{"what": "  유형 변경  ", "at": "forged", "by": "admin"}])
    change = saved["changes"][0]
    assert change["what"] == "유형 변경" and change["src"] == "직접 수정"
    assert change["by"] == saved["updated_by"] == "unauthenticated"
    assert start <= datetime.fromisoformat(change["at"]) <= datetime.now(timezone.utc)

    client.app.dependency_overrides[get_policy_editor] = lambda: "security-2"
    try:
        saved = save(client, saved, changes=[
            {**change, "by": "spoof", "at": "spoof"},
            {"what": "자동 변환 추가", "src": "INC-42", "by": "spoof"},
        ])
    finally:
        client.app.dependency_overrides.clear()
    assert saved["changes"][0] == change
    assert saved["changes"][1]["by"] == saved["updated_by"] == "security-2"


@pytest.mark.parametrize("tag,code,detail", [
    (None, 428, "DRAFT_PRECONDITION_REQUIRED"),
    ('"sha256:stale"', 409, "DRAFT_CONFLICT"),
    ("*", 409, "DRAFT_CONFLICT"),
    ('W/"sha256:stale"', 409, "DRAFT_CONFLICT"),
])
def test_save_rejects_missing_or_unusable_precondition_without_writing(client, tag, code, detail):
    before = save(client)
    headers = {"If-Match": tag} if tag is not None else {}
    response = client.put("/policy/draft", json={"payload": {}, "changes": []}, headers=headers)
    assert response.status_code == code
    assert response.json()["detail"] == detail
    assert response.headers["cache-control"] == "no-store"
    assert draft(client) == before


def test_revision_rejects_stale_writer_after_payload_returns_to_original(client, monkeypatch):
    import app.policy_draft as draft_module

    class FrozenClock:
        @staticmethod
        def now(tz):
            return datetime(2026, 1, 1, tzinfo=tz)

    monkeypatch.setattr(draft_module, "datetime", FrozenClock)
    first = save(client, payload={"value": "A"}, changes=[])
    second = save(client, first, payload={"value": "B"}, changes=[])
    third = save(client, second, payload={"value": "A"}, changes=[])
    assert third["payload"] == first["payload"] and third["updated_at"] == first["updated_at"]
    assert third["etag"] != first["etag"]
    rejected = client.put("/policy/draft", json={"payload": {}, "changes": []},
                          headers={"If-Match": first["etag"]})
    assert rejected.status_code == 409
    assert draft(client) == third


def test_second_process_restores_draft_and_can_publish_it(client):
    assert client.post("/policy/publish", json={"payload": {"schema": 1, "org": "acme"}}).status_code == 200
    saved = save(client)
    assert saved["base_version"] == 1
    actual = run_python("""
import json
from fastapi.testclient import TestClient
from main import app
with TestClient(app) as c:
    draft = c.get('/policy/draft')
    latest = c.get('/policy/latest').json()
    published = c.post('/policy/publish', headers={'If-Match': draft.headers['etag']})
    print(json.dumps({'draft': draft.json(), 'latest': latest,
                      'code': published.status_code, 'published': published.json()}))
""")
    assert actual["draft"] == saved
    assert decode(actual["latest"]) == {"schema": 1, "org": "acme", "version": 1}
    assert actual["code"] == 200 and actual["published"]["version"] == 2
    assert draft(client)["has_draft"] is False
    assert draft(client)["payload"] == {**payload(), "version": 2}


def test_multiple_processes_saving_same_etag_have_one_winner(client):
    before = draft(client)
    script = """
import json, os
from app.policy import PolicyStore
from app.policy_draft import DraftError
s = PolicyStore(db_path=os.environ['POLICY_DB_PATH'])
try:
    s.save_draft({'writer': os.environ['WRITER']}, [],
                 if_match=os.environ['ETAG'], editor=os.environ['WRITER'])
    result = 200
except DraftError as exc:
    result = exc.status_code
print(json.dumps(result))
"""
    with ThreadPoolExecutor(max_workers=4) as pool:
        statuses = list(pool.map(lambda i: run_python(script, WRITER=str(i), ETAG=before["etag"]), range(4)))
    assert sorted(statuses) == [200, 409, 409, 409]
    saved = draft(client)
    assert saved["revision"] == 1
    assert saved["payload"]["writer"] == saved["updated_by"]


def test_save_racing_publish_does_not_drop_successfully_saved_changes(client):
    from app.policy import PolicyStore
    from app.policy_draft import DraftError

    saved = save(client)
    barrier = Barrier(2)

    def action(publishing):
        store = PolicyStore(db_path=os.environ["POLICY_DB_PATH"])
        barrier.wait(timeout=10)
        try:
            if publishing:
                store.publish(if_match=saved["etag"])
            else:
                store.save_draft({"new": "edit"}, [], if_match=saved["etag"], editor="other")
            return 200
        except DraftError as exc:
            return exc.status_code

    with ThreadPoolExecutor(max_workers=2) as pool:
        statuses = list(pool.map(action, [True, False]))
    assert sorted(statuses) == [200, 409]
    if statuses[0] == 200:
        assert draft(client)["has_draft"] is False
        assert draft(client)["payload"] == {**payload(), "version": 1}
    else:
        assert draft(client)["payload"] == {"new": "edit"}
        assert client.get("/policy/latest").status_code == 404


def test_publish_signs_saved_payload_and_clears_draft_atomically(client):
    from app.policy import DsseVerifier

    saved = save(client, payload={**payload(), "version": 999})
    response = client.post("/policy/publish", headers={"If-Match": saved["etag"]})
    assert response.status_code == 200 and response.json()["version"] == 1
    verified = DsseVerifier().verify(client.get("/policy/latest").json(), last_version=None)
    assert verified.payload == {**payload(), "version": 1}
    after = draft(client)
    assert after["payload"] == verified.payload
    assert after["changes"] == [] and after["has_draft"] is False
    assert after["base_version"] == 1 and after["etag"] != saved["etag"]
    assert client.get("/policy/current").json()["active"] is False
    # Neither a retry nor another editor's old save can overwrite the publication.
    assert client.post("/policy/publish", headers={"If-Match": saved["etag"]}).status_code == 409
    assert client.put("/policy/draft", headers={"If-Match": saved["etag"]},
                      json={"payload": {}, "changes": []}).status_code == 409


@pytest.mark.parametrize("direct", [False, True])
def test_publish_cannot_discard_a_draft_without_current_etag(client, direct):
    saved = save(client)
    kwargs = {"json": {"payload": {"rules": []}}} if direct else {}
    assert client.post("/policy/publish", **kwargs).status_code == 428
    assert client.post("/policy/publish", headers={"If-Match": '"stale"'}, **kwargs).status_code == 409
    assert draft(client) == saved and client.get("/policy/latest").status_code == 404
    response = client.post("/policy/publish", headers={"If-Match": saved["etag"]}, **kwargs)
    assert response.status_code == 200
    expected = {"rules": []} if direct else payload()
    assert draft(client)["payload"] == {**expected, "version": 1}
    assert draft(client)["has_draft"] is False


def test_publish_without_saved_draft_or_valid_payload(client):
    empty = draft(client)
    assert client.post("/policy/publish").status_code == 428
    response = client.post("/policy/publish", headers={"If-Match": empty["etag"]})
    assert response.status_code == 409 and response.json()["detail"] == "NO_POLICY_DRAFT"
    assert client.post("/policy/publish", json={"payload": None}).status_code == 422
    assert client.post("/policy/publish", json={}).status_code == 422
    assert draft(client) == empty


def test_signing_key_failure_keeps_draft_and_version(client):
    from app.policy import PRIV_KEY_PATH, store

    assert client.post("/policy/publish", json={"payload": payload()}).status_code == 200
    saved = save(client)
    before = client.get("/policy/latest").json()
    private_key = PRIV_KEY_PATH.read_bytes()
    PRIV_KEY_PATH.unlink()
    response = client.post("/policy/publish", headers={"If-Match": saved["etag"]})
    assert response.status_code == 503
    assert draft(client) == saved and store.next_version() == 2
    assert client.get("/policy/latest").json() == before
    PRIV_KEY_PATH.write_bytes(private_key)
    assert client.post("/policy/publish", headers={"If-Match": saved["etag"]}).json()["version"] == 2


@pytest.mark.parametrize("operation,table", [("INSERT", "policy_bundle"), ("DELETE", "policy_draft")])
def test_storage_failure_rolls_back_publication_and_draft_clear(client, operation, table):
    from app.policy import store

    saved = save(client)
    with sqlite3.connect(os.environ["POLICY_DB_PATH"]) as conn:
        conn.execute(f"""CREATE TRIGGER reject_write BEFORE {operation} ON {table}
            BEGIN SELECT RAISE(ABORT, 'simulated storage failure'); END""")
    with pytest.raises(sqlite3.IntegrityError, match="simulated storage failure"):
        client.post("/policy/publish", headers={"If-Match": saved["etag"]})
    assert draft(client) == saved
    assert client.get("/policy/latest").status_code == 404 and store.next_version() == 1
    with sqlite3.connect(os.environ["POLICY_DB_PATH"]) as conn:
        conn.execute("DROP TRIGGER reject_write")
    assert client.post("/policy/publish", headers={"If-Match": saved["etag"]}).json()["version"] == 1


def test_old_database_adds_draft_table_without_losing_published_state(client):
    from app.policy import PolicyStore, store

    published = store.publish(payload())
    store.record_ack("pc", 1, "applied", None)
    with sqlite3.connect(os.environ["POLICY_DB_PATH"]) as conn:
        conn.execute("DROP TABLE policy_draft")
    upgraded = PolicyStore(db_path=os.environ["POLICY_DB_PATH"])
    upgraded.initialize()
    assert upgraded.latest() == published
    assert upgraded.ack_summary()["applied"] == 1
    assert upgraded.draft()["payload"] == {**payload(), "version": 1}
    save(client)
    assert upgraded.draft() == draft(client)


def test_model_publication_and_pc_deployment_do_not_clear_draft(client):
    from app.policy import make_bundle

    saved = save(client)
    assert client.post("/policy/model/publish", json=MODEL).status_code == 200
    response = client.post("/policy/deploy", json={"bundle": make_bundle({**payload(), "version": 5})})
    assert response.json()["accepted"] is True
    assert draft(client) == saved
    assert client.post("/policy/publish", headers={"If-Match": saved["etag"]}).json()["version"] == 6


def test_case_rule_can_be_saved_with_its_source_then_published(client):
    from tests.test_cases import new_case, close, detail

    case_id = new_case(client)
    assert close(client, case_id, conclusion="legit", rule="주민등록번호가 포함된 입력 → 태그").status_code == 200
    closed = detail(client, case_id)
    # The console supplies the structured rule; the server never interprets prose.
    saved = save(client, changes=[{"what": "자동 변환 추가: 주민등록번호", "src": case_id}])
    assert draft(client)["changes"][0]["src"] == case_id
    assert client.post("/policy/publish", headers={"If-Match": saved["etag"]}).status_code == 200
    assert decode(client.get("/policy/latest").json())["rules"] == payload()["rules"]
    assert detail(client, case_id) == closed


@pytest.mark.parametrize("body", [
    {"payload": None, "changes": []}, {"payload": [], "changes": []},
    {"payload": {}}, {"payload": {}, "changes": None},
    {"payload": {}, "changes": [{"what": "  "}]},
    {"payload": {}, "changes": [{"what": "x", "src": " "}]},
    {"payload": {}, "changes": [{"what": "x", "src": "x" * 129}]},
    {"payload": {}, "changes": [{"what": "x", "extra": True}]},
    {"payload": {}, "changes": [], "extra": True},
    {"payload": {}, "changes": [{"what": "x"}] * 501},
])
def test_invalid_snapshot_is_rejected_without_mutation(client, body):
    before = draft(client)
    response = client.put("/policy/draft", json=body, headers={"If-Match": before["etag"]})
    assert response.status_code == 422
    assert draft(client) == before


def test_browser_can_read_etag_and_send_if_match(client):
    response = client.get("/policy/draft", headers={"Origin": "https://console.example"})
    assert response.status_code == 200
    exposed = response.headers["access-control-expose-headers"].lower()
    assert "etag" in exposed and "content-disposition" in exposed
    preflight = client.options("/policy/draft", headers={
        "Origin": "https://console.example", "Access-Control-Request-Method": "PUT",
        "Access-Control-Request-Headers": "If-Match, Content-Type",
    })
    assert preflight.status_code == 200
    assert "if-match" in preflight.headers["access-control-allow-headers"].lower()


# --- #46: console plaintext must never reach a signed bundle -----------------
SECRET_WORD = "프로젝트-오로라"
SECRET_EXCLUDE = "010-0000-1234"


def console_state():
    return {"dict": [{"word": SECRET_WORD, "type": "회사 고유 단어"}],
            "exclude": [{"value": SECRET_EXCLUDE}], "tab": "dict"}


def test_issue_46_bodyless_publish_never_signs_console_plaintext(client):
    saved = save(client, console_state=console_state())
    assert saved["console_state"] == console_state()
    assert "console" not in saved["payload"]
    response = client.post("/policy/publish", headers={"If-Match": saved["etag"]})
    assert response.status_code == 200
    latest = client.get("/policy/latest").json()
    raw = base64.b64decode(latest["payload"]).decode("utf-8")
    assert decode(latest) == {**payload(), "version": 1}
    assert '"console' not in raw
    for secret in (SECRET_WORD, SECRET_EXCLUDE):
        assert secret not in raw and secret not in json.dumps(latest, ensure_ascii=False)


def test_console_state_is_saved_read_and_kept_after_publish(client):
    assert draft(client)["console_state"] is None
    saved = save(client, console_state=console_state())
    assert draft(client) == saved and saved["console_state"] == console_state()
    # Changing only console_state changes the ETag (optimistic locking covers it).
    edited = {**console_state(), "tab": "exclude"}
    resaved = save(client, saved, console_state=edited)
    assert resaved["etag"] != saved["etag"]
    assert client.put("/policy/draft", headers={"If-Match": saved["etag"]},
                      json={"payload": payload(), "changes": []}).status_code == 409

    assert client.post("/policy/publish", headers={"If-Match": resaved["etag"]}).status_code == 200
    after = draft(client)
    assert after["has_draft"] is False and after["changes"] == []
    assert after["console_state"] == edited
    assert "console" not in after["payload"]
    # A direct-payload publish also keeps it; a later save without it clears it.
    assert client.post("/policy/publish", json={"payload": payload()}).status_code == 200
    assert draft(client)["console_state"] == edited
    assert save(client)["console_state"] is None


def test_console_state_survives_new_process(client):
    from app.policy import PolicyStore

    save(client, console_state=console_state())
    restored = PolicyStore(db_path=os.environ["POLICY_DB_PATH"]).draft()
    assert restored["console_state"] == console_state()
    assert restored == draft(client)


@pytest.mark.parametrize("key", ["console", "console_state"])
@pytest.mark.parametrize("direct", [False, True])
def test_publish_rejects_console_key_in_payload(client, direct, key):
    from app.policy import store

    # "console_state" misplaced inside payload must not be signed either (PR #52 review).
    leaked = {**payload(), key: {"dict": [{"word": SECRET_WORD}]}}
    if direct:
        before = draft(client)
        response = client.post("/policy/publish", json={"payload": leaked})
    else:
        # A legacy draft that still carries payload.console cannot be published.
        before = save(client, payload=leaked)
        response = client.post("/policy/publish", headers={"If-Match": before["etag"]})
    assert response.status_code == 422
    assert response.json()["detail"] == "POLICY_PAYLOAD_CONSOLE_FORBIDDEN"
    assert response.headers["cache-control"] == "no-store"
    assert client.get("/policy/latest").status_code == 404
    assert draft(client) == before and store.next_version() == 1


@pytest.mark.parametrize("value", [[], "text", 1])
def test_console_state_must_be_an_object(client, value):
    before = draft(client)
    response = client.put("/policy/draft", headers={"If-Match": before["etag"]},
                          json={"payload": {}, "changes": [], "console_state": value})
    assert response.status_code == 422
    assert draft(client) == before
