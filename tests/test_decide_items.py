"""/process/decide event items, employee context and partial revert (issue #63)."""
import hashlib
import hmac
import logging

import pytest

from app.decide_items import mask_preview
from app.policy import ActivePolicy
from app.policy_apply import apply_policy_to_detector
from local_ai.detector import Detector

PHONE = "010-1234-5678"
PHONE2 = "010-9999-8888"
EMAIL = "hong@example.com"
TEXT = f"연락처 {PHONE}, 메일 {EMAIL}, 사무실 {PHONE2}"
KEY = "org-test-key"


def mac(value, key=KEY):
    return hmac.new(key.encode(), value.encode(), hashlib.sha256).hexdigest()


def process(client, text=TEXT):
    r = client.post("/process", json={"text": text, "rules_only": True})
    assert r.status_code == 200, r.text
    return r.json()


def decide(client, work_id, **body):
    return client.post("/process/decide", json={"work_id": work_id, **body})


def by_preview(items):
    return {i["preview"]: i for i in items}


@pytest.fixture()
def keyed(monkeypatch):
    monkeypatch.setenv("POLICY_VALUE_HASH_KEY", KEY)


def raw_values_absent(client, *values):
    from app.db import get_conn
    with get_conn() as conn:
        rows = [dict(r) for r in conn.execute("SELECT * FROM event_log")]
    dump = repr(rows)
    return all(v not in dump for v in values)


# --- omitted fields: previous behavior plus server items ----------------------
def test_omitted_fields_keep_previous_behavior(client):
    work = process(client)
    r = decide(client, work["work_id"], action="revert_original")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["outgoing_text"] == TEXT  # whole original, as before
    event = body["event"]
    assert event["user_id"] is None and event["dept"] is None and event["target_ai"] is None
    assert event["reverted"] is True
    assert [i["decision"] for i in event["items"]] == ["reverted"] * 3  # older app: all reverted


@pytest.mark.parametrize("action,decision", [
    ("send_as_is", "raw"), ("send_transformed", "converted"), ("revert_original", "reverted"),
])
def test_item_per_span_with_decision(client, keyed, action, decision):
    work = process(client)
    event = decide(client, work["work_id"], action=action).json()["event"]
    items = event["items"]
    assert [i["type"] for i in items] == ["PHONE", "EMAIL", "PHONE"]
    assert {i["decision"] for i in items} == {decision}
    assert [i["value_hash"] for i in items] == [mac(PHONE), mac(EMAIL), mac(PHONE2)]
    assert [i["preview"] for i in items] == ["***-****-****", "h***@*******.**m", "***-****-****"]
    assert raw_values_absent(client, PHONE, EMAIL, PHONE2)


def test_cancel_has_no_items(client, keyed):
    work = process(client)
    body = decide(client, work["work_id"], action="cancel").json()
    assert body["event"]["items"] == [] and body["outgoing_text"] is None


def test_no_key_means_no_value_hash(client, monkeypatch):
    monkeypatch.delenv("POLICY_VALUE_HASH_KEY", raising=False)
    work = process(client)
    items = decide(client, work["work_id"], action="send_as_is").json()["event"]["items"]
    assert len(items) == 3 and all("value_hash" not in i or i["value_hash"] is None for i in items)


def test_value_hash_matches_policy_hmac_exclude(client, keyed):
    work = process(client)
    item = decide(client, work["work_id"], action="send_as_is").json()["event"]["items"][0]
    det = Detector(None)
    apply_policy_to_detector(det, ActivePolicy(
        org="acme", version=1, keyid="k", rule_count=0, rules=[], types={}, thresholds={},
        expires_at=None, activated_at="t", bundle_sha256="sha256:v1", dict=[],
        exclude=[{"h": "hmac:" + item["value_hash"]}],
    ))
    assert [s["type"] for s in det.detect(f"대표 {PHONE}")] == []


# --- context fields ------------------------------------------------------------
def test_context_fields_and_reason_text_are_stored(client):
    work = process(client)
    r = decide(client, work["work_id"], action="send_as_is", reason="business_need",
               reason_text="  고객 회신용  ", user_id="emp-7", dept="영업1팀", target_ai="chatgpt")
    assert r.status_code == 200, r.text
    event = r.json()["event"]
    assert (event["user_id"], event["dept"], event["target_ai"]) == ("emp-7", "영업1팀", "chatgpt")
    assert event["reason_text"] == "고객 회신용"


@pytest.mark.parametrize("extra", [
    {"reason_text": "이유"},                                   # no reason
    {"reason": "business_need", "reason_text": "   "},         # blank
    {"reason": "business_need", "reason_text": "가" * 501},
    {"user_id": "u" * 65},
    {"dept": "d" * 129},
    {"target_ai": "t" * 129},
    {"reverted": ["[전화번호_1]"]},                            # not revert_original
])
def test_invalid_bodies_are_422_and_keep_the_work(client, extra):
    work = process(client)
    assert decide(client, work["work_id"], action="send_as_is", **extra).status_code == 422
    assert decide(client, work["work_id"], action="cancel").status_code == 200


def test_reverted_list_is_capped(client):
    work = process(client)
    r = decide(client, work["work_id"], action="revert_original", reverted=["[전화번호_1]"] * 501)
    assert r.status_code == 422


# --- partial revert ----------------------------------------------------------------
def test_partial_revert_restores_only_chosen_placeholders(client, keyed):
    work = process(client)
    assert work["masked_text"] == "연락처 [전화번호_1], 메일 [이메일_1], 사무실 [전화번호_2]"
    body = decide(client, work["work_id"], action="revert_original",
                  reverted=["[전화번호_1]", "[전화번호_1]"]).json()
    assert body["outgoing_text"] == f"연락처 {PHONE}, 메일 [이메일_1], 사무실 [전화번호_2]"
    assert [i["decision"] for i in body["event"]["items"]] == ["reverted", "converted", "converted"]
    assert body["restore_available"] is False


def test_empty_reverted_list_sends_masked_text(client):
    work = process(client)
    body = decide(client, work["work_id"], action="revert_original", reverted=[]).json()
    assert body["outgoing_text"] == work["masked_text"]
    assert {i["decision"] for i in body["event"]["items"]} == {"converted"}


@pytest.mark.parametrize("token", ["[전화번호_9]", "[이름_1]", "전화번호_1", "[이메일]"])
def test_unknown_placeholder_is_422_and_work_survives(client, token):
    work = process(client)
    r = decide(client, work["work_id"], action="revert_original", reverted=["[전화번호_1]", token])
    assert r.status_code == 422
    assert r.json()["detail"] == "UNKNOWN_PLACEHOLDER"
    assert decide(client, work["work_id"], action="revert_original",
                  reverted=["[전화번호_1]"]).status_code == 200


def test_literal_placeholder_in_input_is_unknown(client):
    # A placeholder the employee typed is literal text, not a detected value.
    work = process(client, f"[전화번호_1] 은 예시, 실제는 {PHONE}")
    assert work["masked_text"] == "[전화번호_1] 은 예시, 실제는 [전화번호_2]"
    r = decide(client, work["work_id"], action="revert_original", reverted=["[전화번호_1]"])
    assert r.status_code == 422 and r.json()["detail"] == "UNKNOWN_PLACEHOLDER"


def test_restored_value_that_looks_like_a_placeholder_is_not_expanded(client):
    work = process(client, f"{EMAIL} {PHONE}")
    body = decide(client, work["work_id"], action="revert_original",
                  reverted=["[이메일_1]"]).json()
    assert body["outgoing_text"] == f"{EMAIL} [전화번호_1]"


# --- false-positive list ----------------------------------------------------------
def test_false_positive_revert_appears_in_false_positive_list(client, keyed):
    work = process(client)
    r = decide(client, work["work_id"], action="revert_original", reason="false_positive",
               reason_text="회사 대표번호", user_id="emp-1", reverted=["[전화번호_1]"])
    assert r.status_code == 200, r.text
    groups = {g["value_hash"]: g for g in client.get("/false-positives").json()}
    # Only the reverted value is a report; the converted ones stay masked.
    assert set(groups) == {mac(PHONE)}
    g = groups[mac(PHONE)]
    assert (g["report_count"], g["employee_count"], g["types"]) == (1, 1, ["PHONE"])
    assert g["preview"] == "***-****-****"
    assert g["last_event_id"] == r.json()["event"]["id"]

    # A second employee reporting the same value joins the same group.
    work = process(client, f"대표번호 {PHONE}")
    decide(client, work["work_id"], action="revert_original", reason="false_positive",
           user_id="emp-2")
    g = {g["value_hash"]: g for g in client.get("/false-positives").json()}[mac(PHONE)]
    assert (g["report_count"], g["employee_count"]) == (2, 2)


def test_no_raw_value_in_logs(client, keyed, caplog):
    with caplog.at_level(logging.DEBUG):
        work = process(client)
        decide(client, work["work_id"], action="revert_original", reason="false_positive",
               reverted=["[이메일_1]"])
    assert all(v not in caplog.text for v in (PHONE, EMAIL, PHONE2))
    assert raw_values_absent(client, PHONE, EMAIL, PHONE2)


# --- preview ----------------------------------------------------------------------
@pytest.mark.parametrize("kind,value,expected", [
    ("NAME", "윤서아", "윤*아"),
    ("NAME", "윤아", "윤*"),
    ("NAME", "윤", "*"),
    ("ID_NUMBER", "900101-1234567", "******-*******"),
    ("PASSWORD", "hunter2", "********"),
    ("ADDRESS", "서울시 강남구 테헤란로 1", "서** *** **** 1"),
])
def test_mask_preview(kind, value, expected):
    assert mask_preview(kind, value) == expected


def test_mask_preview_is_bounded():
    assert len(mask_preview("ADDRESS", "가" * 500)) <= 30
