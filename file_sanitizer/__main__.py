"""Offline demo with synthetic data. This processor is only for the demo."""

import argparse
from io import BytesIO
from pathlib import Path
from tempfile import mkdtemp

from openpyxl import Workbook
from openpyxl.comments import Comment

from . import Decision, sanitize_xlsx


class DemoProcessor:
    # Fixed synthetic fixtures; the team processor owns real mappings and restoration.
    substitutions = {
        "김민수": "고객 A", "박서연": "고객 B", "이준호": "담당자 A",
        "010-0000-0000": "",
    }
    confidential = "기밀테스트-001"

    def process(self, session_id, segments):
        decisions = {}
        for segment in segments:
            if self.confidential in segment.text:
                decisions[segment.id] = Decision("C")
                continue
            text = segment.text
            for original, alias in self.substitutions.items():
                text = text.replace(original, alias)
            grade = "O" if text == segment.text else "S"
            replacement = text if segment.exportable else None
            if grade == "S" and not text:
                replacement = None
            decisions[segment.id] = Decision(grade, replacement)
        return decisions

    def verify(self, session_id, segments):
        markers = (*self.substitutions, self.confidential)
        return all(marker not in segment.text for segment in segments for marker in markers)


def create_sample():
    book = Workbook()
    sheet = book.active
    sheet.title = "가상업무표"
    for row in [
        ["고객명", "담당자", "요청 내용", "수량", "금액", "연락처", "내부 열"],
        ["김민수", "이준호", "김민수가 일정을 문의함", 2, 39000, "010-0000-0000", "숨김열표식"],
        ["박서연", "이준호", "요청자 박서연 · 자료 요청", 1, 12000],
        ["김민수", "이준호", "김민수가 일정을 다시 확인함", 3, 24000],
        ["숨김행표식"],
    ]:
        sheet.append(row)
    sheet["A2"].comment = Comment("내부메모표식", "메모작성자표식")
    sheet.row_dimensions[5].hidden = True
    sheet.column_dimensions["G"].hidden = True
    for col, width in {"A": 16, "B": 16, "C": 40, "D": 10, "E": 14, "F": 22}.items():
        sheet.column_dimensions[col].width = width
    private = book.create_sheet("숨김시트표식")
    private["A1"] = "내부명단표식"
    private.sheet_state = "hidden"
    book.properties.creator = "문서작성자표식"
    stream = BytesIO()
    book.save(stream)
    book.close()
    return stream.getvalue()


def main():
    parser = argparse.ArgumentParser(description="합성 데이터로 XLSX 파일 보호 모듈을 실행합니다.")
    parser.add_argument("command", choices=["demo"])
    parser.add_argument("--output-dir", type=Path, default=Path("demo-output"))
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    # Isolate runs so a failed or concurrent run can never expose a stale copy.
    directory = Path(mkdtemp(prefix="run-", dir=args.output_dir)).resolve()
    source = create_sample()
    (directory / "원본.xlsx").write_bytes(source)
    result = sanitize_xlsx(source, "demo-session", DemoProcessor(), filename="원본.xlsx")
    if result.status != "READY":
        parser.exit(1, f"{result.status}: {result.reason}\n")
    (directory / "보호본.xlsx").write_bytes(result.file_bytes)
    summary = result.summary
    print(f"{result.status} ({result.grade}) | {directory}")
    print(f"변환 셀 {summary.changed_cells}개 · 제거 메모 {summary.removed_comments}개 · "
          f"숨긴 시트 {summary.removed_sheets}개 · 숨긴 행 {summary.removed_rows}개 · "
          f"숨긴 열 {summary.removed_columns}개 제외")


if __name__ == "__main__":
    main()
