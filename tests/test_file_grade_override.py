from app.file_service import classify_file_types


def test_public_override_keeps_file_public():
    assert classify_file_types(["BUSINESS_NUMBER"], {"BUSINESS_NUMBER": "O"}) == "O"


def test_unknown_type_still_sensitive():
    assert classify_file_types(["NEW_PII"]) == "S"
    assert classify_file_types(["NEW_PII", "BUSINESS_NUMBER"], {"BUSINESS_NUMBER": "O"}) == "S"


def test_override_up_and_default_confidential():
    assert classify_file_types(["BUSINESS_NUMBER"], {"BUSINESS_NUMBER": "C"}) == "C"
    assert classify_file_types(["PHONE"], {"BUSINESS_NUMBER": "O"}) == "S"
    assert classify_file_types(["API_KEY"]) == "C"
    assert classify_file_types([]) == "O"
