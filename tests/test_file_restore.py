"""Restoring AI replies with a file's mapping, and questions linked to it (issue #29)."""
from io import BytesIO
import threading
from types import SimpleNamespace

from openpyxl import Workbook, load_workbook
import pytest

from tests.test_file_api import api, upload, workbook_bytes  # noqa: F401 (fixture)


@pytest.fixture
def linked(api, monkeypatch):
    from app import process_router

    # /process applies the policy to the shared full detector: use the test double.
    monkeypatch.setattr(process_router, "_get_detector", lambda rules_only: api.detector)
    return api


def one_name_file():
    book = Workbook()
    book.active["A1"] = "김민수"  # The file assigns [이름_1].
    stream = BytesIO()
    book.save(stream)
    book.close()
    return stream.getvalue()


def restore(api, work_id, text):
    return api.client.post(f"/files/{work_id}/restore", json={"text": text})


def ask(api, text, file_work_id, **extra):
    return api.client.post("/process", json={"text": text, "file_work_id": file_work_id, **extra})


def assert_unavailable(response):
    assert response.status_code == 404
    assert response.json() == {"detail": "FILE_NOT_AVAILABLE"}
    assert response.headers["cache-control"] == "no-store"


def test_reply_is_restored_with_the_file_mapping_until_expiry(api):
    work_id = upload(api).json()["work_id"]
    copy = api.client.get(f"/files/{work_id}/download")
    book = load_workbook(BytesIO(copy.content))
    first, second = book.active["A2"].value, book.active["A3"].value
    book.close()
    reply = f"{first}님과 {second}님께 연락하세요. [이름_99]는 모릅니다."
    for _ in range(3):  # Files are discussed over several replies.
        response = restore(api, work_id, reply)
        assert response.status_code == 200
        assert response.headers["cache-control"] == "no-store"
        assert response.json() == {
            "text": "김민수님과 박영희님께 연락하세요. [이름_99]는 모릅니다.",
            "unknown": ["[이름_99]"], "blocked": [],
        }
    assert not api.sessions[0].closed.is_set()


def test_restore_needs_no_download_and_never_extends_expiry(api, monkeypatch):
    from app import file_store

    now = [100.0]
    monkeypatch.setattr(file_store, "time", SimpleNamespace(monotonic=lambda: now[0]))
    work_id = upload(api, one_name_file()).json()["work_id"]
    now[0] += 599
    assert restore(api, work_id, "[이름_1]").json()["text"] == "김민수"
    now[0] += 1
    assert_unavailable(restore(api, work_id, "[이름_1]"))
    assert api.sessions[0].closed.is_set()


def test_restore_is_unavailable_without_a_ready_work(api):
    blocked = upload(api, workbook_bytes(lambda b: setattr(
        b["숨김시트"]["A1"], "value", "API_KEY=TEST_KEY_1234567890"))).json()
    failed = upload(api, b"not an xlsx").json()
    for work_id in ("0" * 32, blocked["work_id"], failed["work_id"]):
        assert_unavailable(restore(api, work_id, "[이름_1]"))
    ready = upload(api).json()["work_id"]
    assert restore(api, ready, "x" * 200_001).status_code == 422


def test_linked_question_continues_the_file_numbering(linked):
    work_id = upload(linked, one_name_file()).json()["work_id"]
    text = "박영희가 김민수에게 010-1234-5678로 연락"
    # Unlinked, the question's first name would also be [이름_1].
    alone = linked.client.post("/process", json={"text": text}).json()
    assert alone["masked_text"].startswith("[이름_1]가")

    response = ask(linked, text, work_id)
    assert response.status_code == 200
    body = response.json()
    # The same person keeps the file's placeholder; a new one gets the next number.
    assert body["masked_text"] == "[이름_2]가 [이름_1]에게 [전화번호_1]로 연락"
    assert body["detected_types"] == ["NAME", "PHONE"] and body["detected_count"] == 3
    assert body["grade"] == "sensitive_S" and body["detection_confidence"] == "high"

    reply = "[이름_1]님과 [이름_2]님, [전화번호_1]"
    expected = "김민수님과 박영희님, 010-1234-5678"
    assert restore(linked, work_id, reply).json()["text"] == expected
    decided = linked.client.post("/process/decide", json={
        "work_id": body["work_id"], "action": "send_transformed",
    }).json()
    assert decided["restore_available"] is True and decided["event"]["source"] == "text"
    restored = linked.client.post("/process/restore", json={"work_id": body["work_id"], "text": reply})
    assert restored.json()["text"] == expected
    # The question's own restore is still one-shot; the file's mapping lives on.
    again = linked.client.post("/process/restore", json={"work_id": body["work_id"], "text": reply})
    assert again.status_code == 404
    assert restore(linked, work_id, reply).json()["text"] == expected
    assert not linked.sessions[0].closed.is_set()


def test_follow_up_questions_keep_numbering_and_cancel_keeps_the_mapping(linked):
    work_id = upload(linked, one_name_file()).json()["work_id"]
    first = ask(linked, "박영희 확인", work_id).json()
    linked.client.post("/process/decide", json={"work_id": first["work_id"], "action": "cancel"})
    second = ask(linked, "김민수와 박영희", work_id).json()
    assert second["masked_text"] == "[이름_1]와 [이름_2]"
    # A question's values stay in the file mapping until the file work ends.
    assert restore(linked, work_id, "[이름_2]").json()["text"] == "박영희"
    assert not linked.sessions[0].closed.is_set()


def test_secret_in_a_linked_question_is_never_restored(linked):
    work_id = upload(linked, one_name_file()).json()["work_id"]
    body = ask(linked, "API_KEY=TEST_KEY_1234567890 김민수", work_id).json()
    assert body["grade"] == "confidential_C"
    assert "TEST_KEY" not in body["masked_text"] and "[API키_1]" in body["masked_text"]
    result = restore(linked, work_id, "[API키_1] [이름_1]").json()
    assert result == {"text": "[API키_1] 김민수", "unknown": [], "blocked": ["[API키_1]"]}


def test_quoting_a_file_placeholder_fails_closed(linked):
    work_id = upload(linked, one_name_file()).json()["work_id"]
    response = ask(linked, "[이름_1]의 연락처를 정리해줘", work_id)
    assert response.status_code == 422
    assert "placeholder of the linked file" in response.json()["detail"]
    assert restore(linked, work_id, "[이름_1]").json()["text"] == "김민수"


def test_link_needs_a_live_file_work_and_full_detection(linked, monkeypatch):
    from app import file_store

    assert ask(linked, "김민수", "0" * 32).status_code == 404
    now = [100.0]
    monkeypatch.setattr(file_store, "time", SimpleNamespace(monotonic=lambda: now[0]))
    work_id = upload(linked, one_name_file()).json()["work_id"]
    assert ask(linked, "김민수", work_id, rules_only=True).status_code == 422
    question = ask(linked, "박영희", work_id).json()
    linked.client.post("/process/decide", json={
        "work_id": question["work_id"], "action": "send_transformed",
    })
    now[0] += 600
    response = ask(linked, "김민수", work_id)
    assert response.status_code == 404
    assert response.json()["detail"] == "unknown or expired file_work_id"
    # The question's own work item outlives the file, but the mapping is gone.
    late = linked.client.post("/process/restore", json={"work_id": question["work_id"], "text": "[이름_2]"})
    assert late.status_code == 404
    assert "linked file work has ended" in late.json()["detail"]


def test_borrowed_mapping_never_closes_the_file_mapping():
    from app.file_mapping import MappingClosed, SharedMapping
    from local_ai.detector import Detector
    from local_ai.pipeline import LocalSession

    shared = SharedMapping(LocalSession(Detector(None)))
    borrowed = shared.borrow()
    assert borrowed.process("010-1234-5678").text == "[전화번호_1]"
    borrowed.close()
    with pytest.raises(MappingClosed):
        borrowed.restore("[전화번호_1]")
    assert shared.restore("[전화번호_1]").text == "010-1234-5678"
    other = shared.borrow()
    shared.close()
    with pytest.raises(MappingClosed):
        other.process("x")


def test_ending_a_work_never_waits_for_or_cuts_off_a_restore(monkeypatch):
    from app import file_store
    from local_ai.pseudonym import RestoreResult

    class SlowSession:
        def __init__(self):
            self.entered, self.release, self.closed = (threading.Event() for _ in range(3))

        def restore(self, text):
            self.entered.set()
            assert self.release.wait(5)
            assert not self.closed.is_set()  # Never closed under an active restore.
            return RestoreResult(text, (), ())

        def close(self):
            self.closed.set()

    now = [100.0]
    monkeypatch.setattr(file_store, "time", SimpleNamespace(monotonic=lambda: now[0]))
    store = file_store.FileWorkStore(ttl_seconds=10)
    session = SlowSession()
    store.add(work_id="one", file_bytes=b"copy", session=session, grade=None, summary=None)
    mapping = store.lend("one")  # A linked question's handle, taken before expiry.
    results = {}
    restoring = threading.Thread(target=lambda: results.update(r=store.restore("one", "x")))
    restoring.start()
    assert session.entered.wait(5)
    queued = threading.Thread(target=lambda: results.update(q=_closed_error(mapping)))
    queued.start()  # Waits for its turn behind the restore.
    now[0] += 10
    # Purging the expired work returns at once (add runs under the job lock,
    # discard on the event loop); the mapping closes when the restore is done.
    assert len(store) == 0
    assert not session.closed.is_set()
    session.release.set()
    restoring.join(5)
    queued.join(5)
    assert results["r"].text == "x"
    assert session.closed.is_set()
    assert results["q"] is True  # The next use in line finds the mapping ended.


def _closed_error(mapping):
    from app.file_mapping import MappingClosed

    try:
        mapping.restore("[이름_1]")
    except MappingClosed:
        return True
    return False


def test_placeholder_reuse_is_a_pseudonym_error():
    from local_ai.pseudonym import PlaceholderReuseError, PseudonymError, PseudonymSession

    session = PseudonymSession()
    session.pseudonymize("김민수", [{"start": 0, "end": 3, "type": "NAME"}])
    with pytest.raises(PlaceholderReuseError) as raised:
        session.pseudonymize("[이름_1] 확인", [])
    assert isinstance(raised.value, PseudonymError)
