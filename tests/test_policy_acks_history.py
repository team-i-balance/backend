"""Issue #25: per-version ack counts, publish history, console types mapping."""
from datetime import datetime, timezone

from local_ai.pseudonym import _TYPE_LABELS


def _payload(rules=0, types=None):
    p = {
        "schema": 1,
        "org": "acme",
        "expires_at": "2999-01-01T00:00:00+00:00",
        "thresholds": {"confidential": 0.45, "personal": 0.35, "high_confidence": 0.7},
        "rules": [
            {"id": f"r-{i}", "label": "고객ID", "description": "d", "grade": "S", "action": "대체"}
            for i in range(rules)
        ],
    }
    if types is not None:
        p["types"] = types
    return p


def _publish(client, rules=0):
    r = client.post("/policy/publish", json={"payload": _payload(rules)})
    assert r.status_code == 200
    return r.json()


def _ack(client, device, version, status, reason=None):
    body = {"device_id": device, "version": version, "status": status}
    if reason is not None:
        body["reason"] = reason
    r = client.post("/policy/ack", json=body)
    assert r.status_code == 200


# --- per-version acks -------------------------------------------------------
def test_version_acks_separates_versions(client):
    _publish(client)
    _publish(client)
    _ack(client, "pc-1", 1, "applied")
    _ack(client, "pc-2", 1, "rejected", "expired")
    _ack(client, "pc-1", 2, "applied")
    _ack(client, "pc-2", 2, "rejected", "model_mismatch")
    _ack(client, "pc-3", 2, "rejected", "model_mismatch")

    v1 = client.get("/policy/1/acks").json()
    assert v1 == {"version": 1, "devices": 2, "applied": 1, "rejected": 1,
                  "reject_reasons": {"expired": 1}}
    v2 = client.get("/policy/2/acks").json()
    assert v2 == {"version": 2, "devices": 3, "applied": 1, "rejected": 2,
                  "reject_reasons": {"model_mismatch": 2}}


def test_version_acks_resend_counts_last_only(client):
    _publish(client)
    _ack(client, "pc-1", 1, "rejected", "rollback")
    _ack(client, "pc-1", 1, "rejected", "expired")
    _ack(client, "pc-1", 1, "applied")
    _ack(client, "pc-2", 1, "rejected", "rollback")
    _ack(client, "pc-2", 1, "rejected", "expired")
    s = client.get("/policy/1/acks").json()
    assert s["devices"] == 2
    assert s["applied"] == 1
    assert s["rejected"] == 1
    assert s["reject_reasons"] == {"expired": 1}


def test_version_acks_later_version_does_not_erase_earlier(client):
    # The old /policy/acks overwrote per device; per-version keeps both.
    _publish(client)
    _publish(client)
    _ack(client, "pc-1", 1, "applied")
    _ack(client, "pc-1", 2, "rejected", "expired")
    assert client.get("/policy/1/acks").json()["applied"] == 1
    assert client.get("/policy/2/acks").json()["rejected"] == 1


def test_version_acks_published_but_no_acks_is_zero(client):
    _publish(client)
    assert client.get("/policy/1/acks").json() == {
        "version": 1, "devices": 0, "applied": 0, "rejected": 0, "reject_reasons": {},
    }


def test_version_acks_unknown_version_404(client):
    assert client.get("/policy/9/acks").status_code == 404


def test_version_acks_for_unpublished_version_with_acks(client):
    # Acks are accepted for any version (devices may hold bundles from
    # another server instance); counts are still reported.
    _ack(client, "pc-1", 5, "applied")
    assert client.get("/policy/5/acks").json()["applied"] == 1


def test_rejected_without_reason_not_in_reasons(client):
    _publish(client)
    _ack(client, "pc-1", 1, "rejected")
    s = client.get("/policy/1/acks").json()
    assert s["rejected"] == 1
    assert s["reject_reasons"] == {}


# --- legacy /policy/acks + ?version ------------------------------------------
def test_legacy_acks_shape_unchanged(client):
    _ack(client, "pc-1", 1, "rejected", "rollback")
    _ack(client, "pc-1", 2, "applied")
    body = client.get("/policy/acks").json()
    assert set(body) == {"ok", "summary"}
    assert body["summary"] == {"devices": 1, "applied": 1, "rejected": 0, "reject_reasons": {}}


def test_legacy_acks_version_query(client):
    _ack(client, "pc-1", 1, "rejected", "rollback")
    _ack(client, "pc-2", 1, "applied")
    _ack(client, "pc-1", 2, "applied")
    v1 = client.get("/policy/acks", params={"version": 1}).json()
    assert set(v1) == {"ok", "summary"}
    assert v1["summary"] == {"devices": 2, "applied": 1, "rejected": 1,
                             "reject_reasons": {"rollback": 1}}
    v2 = client.get("/policy/acks?version=2").json()["summary"]
    assert v2 == {"devices": 1, "applied": 1, "rejected": 0, "reject_reasons": {}}
    empty = client.get("/policy/acks?version=7").json()["summary"]
    assert empty["devices"] == 0


def test_legacy_acks_version_query_must_be_int(client):
    assert client.get("/policy/acks?version=abc").status_code == 422


# --- history -----------------------------------------------------------------
def test_history_empty(client):
    r = client.get("/policy/history")
    assert r.status_code == 200
    assert r.json() == []


def test_history_newest_first_with_fields(client):
    p1 = _publish(client, rules=0)
    p2 = _publish(client, rules=2)
    p3 = _publish(client, rules=1)
    items = client.get("/policy/history").json()
    assert [i["version"] for i in items] == [3, 2, 1]
    assert [i["rule_count"] for i in items] == [1, 2, 0]
    assert [i["sha256"] for i in items] == [p3["bundle_sha256"], p2["bundle_sha256"], p1["bundle_sha256"]]
    for item in items:
        assert set(item) == {"version", "sha256", "stored_at", "rule_count"}
        at = datetime.fromisoformat(item["stored_at"])
        assert at.utcoffset() == timezone.utc.utcoffset(None)
    # sha256 matches the stored bundle's ETag
    assert client.get("/policy/latest").headers["ETag"] == items[0]["sha256"]


def test_history_route_not_shadowed_by_version(client):
    _publish(client)
    # /policy/{version} still works and /policy/history is not parsed as a version.
    assert client.get("/policy/1").status_code == 200
    assert client.get("/policy/history").status_code == 200


def test_history_missing_stored_at_is_null(client):
    from app.policy import StoredBundle, store
    store._history[1] = StoredBundle(version=1, envelope={}, sha256="sha256:x", stored_at=None)
    store._latest_version = 1
    assert client.get("/policy/history").json() == [
        {"version": 1, "sha256": "sha256:x", "stored_at": None, "rule_count": 0}
    ]


def test_history_rule_count_non_list_rules_is_zero(client):
    r = client.post("/policy/publish", json={"payload": {**_payload(), "rules": "x"}})
    assert r.status_code == 200
    assert client.get("/policy/history").json()[0]["rule_count"] == 0


# --- console types mapping ---------------------------------------------------
# Console items (team-i-balance/web src/domain/seed.ts) -> detector type.
EXPECTED_MAPPING = {
    "이름": "NAME",
    "전화번호": "PHONE",
    "이메일": "EMAIL",
    "주소": "ADDRESS",
    "생년월일": "DOB",
    "계좌번호": "ACCOUNT",
    "카드번호": "CARD",
    "주민등록번호": "ID_NUMBER",
    "API 키": "API_KEY",
    "API키": "API_KEY",
    "비밀번호": "PASSWORD",
    "사업자번호": "BUSINESS_NUMBER",
    "토큰": "ACCESS_TOKEN",
}
CONSOLE_ITEMS = [
    "이름", "전화번호", "이메일", "주소", "나이", "생년월일", "계좌번호", "고객ID",
    "카드번호", "주민등록번호", "프로젝트 코드명", "API 키", "비밀번호", "미공개 실적",
    "사업자번호",
]
UNMAPPED_CONSOLE_ITEMS = {"나이", "고객ID", "프로젝트 코드명", "미공개 실적"}


def test_mapping_table_is_fixed():
    from app.policy_apply import _CATEGORY_TO_DETECTOR_TYPE
    assert _CATEGORY_TO_DETECTOR_TYPE == EXPECTED_MAPPING


def test_mapping_targets_are_known_detection_types():
    from app.policy_apply import _CATEGORY_TO_DETECTOR_TYPE
    assert set(_CATEGORY_TO_DETECTOR_TYPE.values()) <= set(_TYPE_LABELS)


def test_console_items_mapped_or_listed_unmapped():
    from app.policy_apply import _CATEGORY_TO_DETECTOR_TYPE
    unmapped = {c for c in CONSOLE_ITEMS if c not in _CATEGORY_TO_DETECTOR_TYPE}
    assert unmapped == UNMAPPED_CONSOLE_ITEMS


def test_console_payload_all_off_disables_mapped_types():
    from app.policy import ActivePolicy
    from app.policy_apply import disabled_detector_types
    pol = ActivePolicy(
        org="acme", version=1, keyid="k", rule_count=0, rules=[],
        types={name: {"on": False} for name in CONSOLE_ITEMS},
        thresholds={}, expires_at=None, activated_at="t", bundle_sha256="sha256:x",
    )
    assert disabled_detector_types(pol) == {
        "NAME", "PHONE", "EMAIL", "ADDRESS", "DOB", "ACCOUNT", "CARD",
        "ID_NUMBER", "API_KEY", "PASSWORD", "BUSINESS_NUMBER",
    }


def test_console_api_key_with_space_turns_off_api_key_detection():
    from local_ai.detector import Detector
    from app.policy import ActivePolicy
    from app.policy_apply import apply_policy_to_detector
    text = "api_key=sk-abcdefghijklmnopqrstuvwx1234"
    d = Detector(None)
    assert any(x["type"] == "API_KEY" for x in d.detect(text))
    pol = ActivePolicy(
        org="acme", version=1, keyid="k", rule_count=0, rules=[],
        types={"API 키": {"on": False}}, thresholds={}, expires_at=None,
        activated_at="t", bundle_sha256="sha256:x",
    )
    apply_policy_to_detector(d, pol)
    assert not any(x["type"] == "API_KEY" for x in d.detect(text))
