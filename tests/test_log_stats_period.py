"""Period statistics and pagination over more than one page of events."""
import pytest


def seed(rows):
    from app.db import get_conn

    with get_conn() as conn:
        conn.executemany(
            """INSERT INTO event_log
               (created_at, request_id, grade, action, reason, reverted, queue)
               VALUES (:at, :request_id, :grade, :action, :reason, :reverted, :queue)""",
            [{"at": "2026-06-01T12:00:00+00:00", "request_id": None,
              "grade": "sensitive_S", "action": "send_transformed",
              "reason": None, "reverted": 0, "queue": "pre_warning", **row}
             for row in rows],
        )


def stats(client, **params):
    response = client.get("/logs/stats", params=params)
    assert response.status_code == 200
    return response.json()


def events(client, **params):
    response = client.get("/logs/events", params=params)
    assert response.status_code == 200
    assert isinstance(response.json(), list)
    return response.json()


def test_all_statistics_use_the_same_inclusive_period(client):
    seed([
        {"at": "2026-05-31T23:59:59Z", "reason": "business_need", "reverted": 1},
        {"at": "2026-06-01T00:00:00Z", "grade": "public_O", "action": "send_as_is"},
        {"at": "2026-06-01T12:00:00Z"},
        {"at": "2026-06-01T13:00:00Z", "grade": "confidential_C", "action": "cancel"},
        {"at": "2026-06-01T14:00:00Z", "action": "revert_original", "reverted": 1,
         "reason": "business_need", "queue": "violation_candidate"},
        {"at": "2026-06-02T00:00:00Z", "action": "revert_original", "reverted": 1,
         "reason": "false_positive", "queue": "detection_improve"},
        {"at": "2026-06-02T00:00:00.000001Z", "reason": "business_need", "reverted": 1},
    ])
    params = {"start": "2026-06-01T09:00:00+09:00", "end": "2026-06-02T00:00:00Z"}
    result = stats(client, **params)
    assert result == {
        "total": 5, "acceptance_rate": 0.4, "revert_rate": 0.4, "evasion_suspect": 1,
        "by_action": {"send_as_is": 1, "send_transformed": 1, "cancel": 1, "revert_original": 2},
        "by_grade": {"public_O": 1, "sensitive_S": 3, "confidential_C": 1},
        "by_queue": {"pre_warning": 3, "violation_candidate": 1, "detection_improve": 1},
        "by_policy_version": {"none": 5},
    }
    assert len(events(client, **params)) == result["total"]
    assert stats(client)["total"] == 7  # No bounds retains all-time behavior.


@pytest.mark.parametrize("params,expected", [
    ({"start": "2026-06-01T12:00:00Z"}, ["middle", "last"]),
    ({"end": "2026-06-01T12:00:00"}, ["first", "middle"]),
    ({"start": "2026-06-01", "end": "2026-06-01"}, ["first"]),
    ({"start": "2026-06-01T21:00:00+09:00", "end": "2026-06-01T10:00:00-02:00"}, ["middle"]),
    ({"start": "2027-01-01T00:00:00Z"}, []),
])
def test_one_sided_naive_date_and_offset_boundaries(client, params, expected):
    seed([
        {"at": "2026-06-01T00:00:00+00:00", "request_id": "first"},
        {"at": "2026-06-01T21:00:00+09:00", "request_id": "middle"},
        {"at": "2026-06-02T00:00:00", "request_id": "last"},
    ])
    result = stats(client, **params)
    assert result["total"] == len(expected)
    assert {e["request_id"] for e in events(client, **params)} == set(expected)
    assert result["by_action"]["send_transformed"] == len(expected)


def test_microsecond_boundaries_do_not_round_into_or_out_of_window(client):
    seed([
        {"at": "2026-06-01T12:00:00.999998Z", "request_id": "before"},
        {"at": "2026-06-01T12:00:00.999999+00:00", "request_id": "boundary"},
        {"at": "2026-06-01T12:00:01Z", "request_id": "after"},
    ])
    params = {"start": "2026-06-01T12:00:00.999999Z", "end": "2026-06-01T21:00:00.999999+09:00"}
    assert stats(client, **params)["total"] == 1
    assert [e["request_id"] for e in events(client, **params)] == ["boundary"]


def test_empty_window_returns_zero_counts_for_all_actions(client):
    seed([{}])
    result = stats(client, start="2027-01-01T00:00:00Z")
    assert result == {
        "total": 0, "acceptance_rate": 0.0, "revert_rate": 0.0, "evasion_suspect": 0,
        "by_queue": {}, "by_grade": {},
        "by_action": {"send_as_is": 0, "send_transformed": 0, "cancel": 0, "revert_original": 0},
        "by_policy_version": {},
    }


def test_statistics_count_over_1000_events_and_every_page_is_reachable(client):
    seed(
        [{"action": "send_as_is", "grade": "public_O"}] * 501
        + [{"action": "send_transformed"}] * 201
        + [{"action": "cancel", "grade": "confidential_C"}] * 155
        + [{"action": "revert_original", "reverted": 1,
            "reason": "business_need", "queue": "violation_candidate"}] * 150
        + [{"at": "2026-05-01T00:00:00Z"}] * 10
    )
    params = {"start": "2026-06-01", "end": "2026-06-02"}
    result = stats(client, **params)
    assert result["total"] == 1007
    assert result["by_action"] == {
        "send_as_is": 501, "send_transformed": 201, "cancel": 155, "revert_original": 150,
    }
    assert result["acceptance_rate"] == round(702 / 1007, 4)
    assert result["revert_rate"] == round(150 / 1007, 4)
    assert result["evasion_suspect"] == 150
    assert sum(result["by_queue"].values()) == sum(result["by_grade"].values()) == 1007
    assert len(events(client, limit=1000, **params)) == 1000
    seen, cursor = [], None
    for _ in range(20):
        rows = events(client, limit=123, **params, **({"cursor": cursor} if cursor else {}))
        seen.extend(row["id"] for row in rows)
        if not rows:
            break
        cursor = rows[-1]["id"]
    else:
        pytest.fail("cursor never reached the end")
    assert seen == list(range(1007, 0, -1))
    assert len(seen) == len(set(seen)) == result["total"]


def test_new_events_do_not_shift_cursor_pages(client):
    seed([{}] * 5)
    first = events(client, limit=2)
    assert [e["id"] for e in first] == [5, 4]
    seed([{}])  # New head while reading the older pages.
    second = events(client, limit=2, cursor=first[-1]["id"])
    third = events(client, limit=2, cursor=second[-1]["id"])
    assert [e["id"] for e in first + second + third] == [5, 4, 3, 2, 1]
    assert events(client, cursor=third[-1]["id"]) == []
    assert events(client, limit=1)[0]["id"] == 6


def test_cursor_combines_with_grade_queue_and_period_filters(client):
    seed([
        {"request_id": "match-1", "queue": "violation_candidate"},
        {"grade": "public_O", "queue": "violation_candidate"},
        {"request_id": "match-2", "queue": "violation_candidate"},
        {"at": "2025-01-01T00:00:00Z", "queue": "violation_candidate"},
        {"queue": "detection_improve"},
        {"request_id": "match-3", "queue": "violation_candidate"},
    ])
    params = {"grade": "sensitive_S", "queue": "violation_candidate",
              "start": "2026-06-01", "end": "2026-06-02", "limit": 2}
    first = events(client, **params)
    second = events(client, **params, cursor=first[-1]["id"])
    assert [e["request_id"] for e in first + second] == ["match-3", "match-2", "match-1"]


@pytest.mark.parametrize("route", ["/logs/stats", "/logs/events"])
@pytest.mark.parametrize("params", [
    {"start": "not-a-date"}, {"end": "2026-13-99"},
    {"start": "2026-01-01Z"},
    {"end": "2026-06-01T12:00:00+09:00Z"},
    {"start": ""}, {"end": ""},
    {"start": "2026-06-02", "end": "2026-06-01"},
    {"start": "2026-06-01T00:00:00Z", "end": "2026-06-01T01:00:00+02:00"},
    {"start": "0001-01-01T00:00:00+01:00"},
    {"end": "9999-12-31T23:00:00-02:00"},
])
def test_invalid_and_reversed_periods_return_400(client, route, params):
    assert client.get(route, params=params).status_code == 400


@pytest.mark.parametrize("cursor", [0, -1, 2**63, "abc", "1.5", ""])
def test_invalid_cursors_return_422(client, cursor):
    assert client.get("/logs/events", params={"cursor": cursor}).status_code == 422


def test_old_bad_timestamp_still_counts_in_all_time_stats_but_not_in_period(client):
    seed([{"at": "bad historical timestamp"}, {}])
    assert stats(client)["total"] == 2
    assert stats(client, start="2026-01-01")["total"] == 1
    assert len(events(client, start="2026-01-01")) == 1


def test_openapi_describes_period_stats_and_cursor_without_changing_list_shape(client):
    schema = client.get("/openapi.json").json()
    stats_route = schema["paths"]["/logs/stats"]["get"]
    assert {p["name"] for p in stats_route["parameters"]} >= {"start", "end"}
    list_route = schema["paths"]["/logs/events"]["get"]
    assert "cursor" in {p["name"] for p in list_route["parameters"]}
    assert list_route["responses"]["200"]["content"]["application/json"]["schema"]["type"] == "array"
    assert "by_action" in schema["components"]["schemas"]["Stats"]["properties"]
