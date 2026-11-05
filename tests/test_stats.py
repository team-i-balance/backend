"""Aggregation tests for GET /logs/stats (rules.md section 5)."""


def _event(**kw):
    base = {"grade": "sensitive_S", "action": "send_transformed"}
    base.update(kw)
    return base


def test_stats_empty(client):
    s = client.get("/logs/stats").json()
    assert s == {
        "total": 0,
        "acceptance_rate": 0.0,
        "revert_rate": 0.0,
        "evasion_suspect": 0,
        "by_queue": {},
        "by_grade": {},
        "by_action": {"send_as_is": 0, "send_transformed": 0, "cancel": 0, "revert_original": 0},
        "by_policy_version": {},
    }


def test_stats_computed_values(client):
    # Build a known dataset:
    #  - 2 accepted (send_as_is, send_transformed)
    #  - 1 cancel (not accepted)
    #  - 1 reverted
    #  - 1 business_need (evasion suspect)
    client.post("/logs/events", json=_event(grade="public_O", action="send_as_is"))
    client.post("/logs/events", json=_event(action="send_transformed"))
    client.post("/logs/events", json=_event(action="cancel",
                                            detection_confidence="high"))
    client.post("/logs/events", json=_event(action="revert_original",
                                            reverted=True))
    client.post("/logs/events", json=_event(action="revert_original",
                                            reason="business_need"))

    s = client.get("/logs/stats").json()
    assert s["total"] == 5
    # accepted = send_as_is + send_transformed = 2 / 5
    assert s["acceptance_rate"] == 0.4
    # reverted = 1 / 5
    assert s["revert_rate"] == 0.2
    # business_need = 1
    assert s["evasion_suspect"] == 1
    assert sum(s["by_queue"].values()) == 5
    assert sum(s["by_grade"].values()) == 5
    assert s["by_grade"]["public_O"] == 1
    assert s["by_grade"]["sensitive_S"] == 4
    assert s["by_action"] == {"send_as_is": 1, "send_transformed": 1, "cancel": 1, "revert_original": 2}


def test_acceptance_rate_all_accepted(client):
    client.post("/logs/events", json=_event(action="send_as_is"))
    client.post("/logs/events", json=_event(action="send_transformed"))
    s = client.get("/logs/stats").json()
    assert s["acceptance_rate"] == 1.0
    assert s["revert_rate"] == 0.0
