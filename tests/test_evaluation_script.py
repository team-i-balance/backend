import tempfile
import unittest
from pathlib import Path

from evaluation.evaluate_secret_rule_candidates import run


class EvaluationInputValidationTests(unittest.TestCase):
    def test_duplicate_basenames_fail_instead_of_overwriting_dataset_rows(self):
        with tempfile.TemporaryDirectory() as directory:
            first = Path(directory) / "first" / "data.jsonl"
            second = Path(directory) / "second" / "data.jsonl"
            first.parent.mkdir()
            second.parent.mkdir()
            first.write_text('{"text":"first","annotations":[]}\n', encoding="utf-8")
            second.write_text('{"text":"second","annotations":[]}\n', encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "duplicate basename.*data.jsonl"):
                run([first, second])


if __name__ == "__main__":
    unittest.main()
