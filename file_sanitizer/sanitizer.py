from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from io import BytesIO
from typing import Literal, Protocol
from uuid import uuid4

from openpyxl import Workbook, load_workbook
from openpyxl.cell.cell import Cell
from openpyxl.utils import get_column_letter
from openpyxl.utils.datetime import CALENDAR_MAC_1904

from .number_format import day_zero_value, display_policy, format_labels
from .package import MAX_GRID, RejectedFile, inspect_package

Grade = Literal["O", "S", "C"]


@dataclass(frozen=True)
class Segment:
    id: str
    text: str
    column_header: str | None = None
    exportable: bool = False


@dataclass(frozen=True)
class Decision:
    grade: Grade
    text: str | None = None  # For exportable cells: replacement, or None to clear.


class ResidualPIIError(ValueError):
    """The processor still found sensitive text after its transformation."""


class Processor(Protocol):
    def process(self, session_id: str, segments: Sequence[Segment]) -> Mapping[str, Decision]:
        """Review every segment, including private metadata, using the same session."""
        ...

    def verify(self, session_id: str, segments: Sequence[Segment]) -> bool:
        """Read-only residual scan of the serialized copy, without creating mappings."""
        ...


@dataclass(frozen=True)
class Summary:
    changed_cells: int
    removed_comments: int
    removed_sheets: int
    removed_rows: int
    removed_columns: int


@dataclass(frozen=True)
class Result:
    status: Literal["READY", "BLOCKED", "FAILED"]
    processing_id: str
    reason: str | None = None
    grade: Grade | None = None
    file_bytes: bytes | None = None
    summary: Summary | None = None


@dataclass
class Inspection:
    segments: list[Segment]
    # Only visible, nonempty cells are eligible for writing to the new workbook.
    visible_sheets: list[list[tuple[str, Cell]]]
    comments: int = 0
    hidden_sheets: int = 0
    hidden_rows: int = 0
    hidden_columns: int = 0
    hidden_format_cells: int = 0
    unsupported_format: bool = False
    display_texts: dict[str, str] = field(default_factory=dict)
    output_formats: dict[str, str] = field(default_factory=dict)


def read_xlsx(data, filename=None):
    properties, serials_by_sheet = inspect_package(data)
    if filename:
        properties["filename"] = filename
    scan = Inspection([Segment(key, text) for key, text in properties.items()], [])
    for key, text in properties.items():
        if key.startswith("number-format:"):
            scan.segments.extend(Segment(f"{key}:label:{i}", label)
                                 for i, label in enumerate(format_labels(text)))
    # Preflight rejects formulas except literal booleans whose cached value was validated.
    book = load_workbook(BytesIO(data), data_only=True, keep_links=False)
    try:
        for index, sheet in enumerate(book.worksheets, 1):
            prefix = f"s{index}"
            serials = serials_by_sheet[index - 1]
            scan.segments.append(Segment(f"{prefix}:title", sheet.title))
            visible = sheet.sheet_state == "visible"
            export_cells = []
            if visible:
                scan.visible_sheets.append(export_cells)
            else:
                scan.hidden_sheets += 1
            # openpyxl does not apply inherited row/column formats to Cell.
            # Refuse these rather than treating a concealed cell as General.
            if any(d.number_format != "General"
                   for dimensions in (sheet.row_dimensions, sheet.column_dimensions)
                   for d in dimensions.values()):
                scan.unsupported_format = True
            hidden_rows = {d.index for d in sheet.row_dimensions.values() if d.hidden or d.height == 0}
            hidden_cols = set()
            for d in sheet.column_dimensions.values():
                if d.hidden or d.width == 0:
                    if not (1 <= d.min <= d.max <= 16384):
                        raise RejectedFile("INVALID_XLSX")
                    hidden_cols.update(range(d.min, d.max + 1))
            scan.hidden_rows += len(hidden_rows)
            scan.hidden_columns += len(hidden_cols)
            if sheet.max_row * sheet.max_column > MAX_GRID:
                raise RejectedFile("FILE_TOO_LARGE")
            for row in sheet.iter_rows():
                for cell in row:
                    key = f"{prefix}:{cell.coordinate}"
                    if cell.comment:
                        scan.comments += 1
                        scan.segments.append(Segment(key + ":comment", cell.comment.text))
                        scan.segments.append(Segment(key + ":author", cell.comment.author or ""))
                    if cell.value is None:
                        continue
                    if cell.data_type in {"e", "f"}:
                        raise RejectedFile("UNSUPPORTED_FEATURE")
                    raw_numeric = serials.get((cell.row, cell.column))
                    if book.epoch == CALENDAR_MAC_1904 and raw_numeric is not None and 0 <= float(raw_numeric) < 1:
                        cell.value = day_zero_value(raw_numeric, cell.number_format)
                    export = visible and cell.row not in hidden_rows and cell.column not in hidden_cols
                    hidden, safe_format = display_policy(cell.value, cell.number_format, raw_numeric)
                    scan.unsupported_format |= safe_format is None
                    scan.hidden_format_cells += bool(export and hidden)
                    export = export and not hidden
                    header = sheet.cell(1, cell.column).value
                    header_text = None if header is None else str(header)
                    text = str(cell.value)
                    if safe_format not in (None, "General"):
                        integer = int(cell.value)
                        text = ("-" if integer < 0 else "") + str(abs(integer)).zfill(len(safe_format))
                        scan.output_formats[key] = safe_format
                        if text != str(cell.value):
                            scan.segments.append(Segment(key + ":raw", str(cell.value), header_text))
                    scan.display_texts[key] = text
                    scan.segments.append(Segment(key, text, header_text, export))
                    if export:
                        export_cells.append((key, cell))
        if not scan.visible_sheets:
            raise RejectedFile("INVALID_XLSX")
        return scan
    finally:
        book.close()


def build_copy(scan, decisions):
    # ISO serialization distinguishes a calendar date from a datetime at midnight.
    book = Workbook(iso_dates=True)
    book.remove(book.active)
    book.properties.creator = None
    changed = scan.hidden_format_cells
    expected = {}
    try:
        for index, cells in enumerate(scan.visible_sheets, 1):
            sheet = book.create_sheet(f"시트{index}")
            for key, original in cells:
                replacement = decisions[key].text
                unchanged = replacement == scan.display_texts[key]
                value = original.value if unchanged else replacement
                changed += value != original.value
                if value is None or value == "":
                    continue
                target = sheet[original.coordinate]
                target.value = value
                if unchanged and key in scan.output_formats:
                    target.number_format = scan.output_formats[key]
                if isinstance(value, str):
                    # Keep even '=...' and '#REF!' as literal text.
                    target.data_type = "s"
                expected[f"s{index}:{target.coordinate}"] = replacement
                width = min(80, 5 + 2 * len(replacement))
                col = sheet.column_dimensions[get_column_letter(target.column)]
                col.width = max(col.width, width)
        stream = BytesIO()
        book.save(stream)
        return stream.getvalue(), expected, changed
    finally:
        book.close()


def sanitize_xlsx(
    file_bytes: bytes, session_id: str, processor: Processor, *, filename: str | None = None
) -> Result:
    """Return verified bytes only on READY. All document data stays with the injected processor."""
    processing_id = uuid4().hex
    if not isinstance(session_id, str) or not session_id.strip() or not isinstance(file_bytes, bytes):
        return Result("FAILED", processing_id, "INVALID_INPUT")
    if filename is not None and (not isinstance(filename, str) or not filename.lower().endswith(".xlsx")):
        return Result("FAILED", processing_id, "UNSUPPORTED_FILE_TYPE")
    try:
        source = read_xlsx(file_bytes, filename)
    except RejectedFile as exc:
        return Result("FAILED", processing_id, str(exc))
    except Exception:
        # Broken containers and malformed OOXML can raise several parser-specific exceptions.
        return Result("FAILED", processing_id, "INVALID_XLSX")

    try:
        decisions = processor.process(session_id, tuple(source.segments))
        if not isinstance(decisions, Mapping) or set(decisions) != {s.id for s in source.segments}:
            return Result("FAILED", processing_id, "INVALID_PROCESSOR_RESULT")
        for segment in source.segments:
            decision = decisions[segment.id]
            if not isinstance(decision, Decision) or decision.grade not in ("O", "S", "C"):
                return Result("FAILED", processing_id, "INVALID_PROCESSOR_RESULT")
            if decision.text is not None and not isinstance(decision.text, str):
                return Result("FAILED", processing_id, "INVALID_PROCESSOR_RESULT")
            if segment.exportable and decision.grade == "O" and decision.text != segment.text:
                return Result("FAILED", processing_id, "INVALID_PROCESSOR_RESULT")
        grades = {d.grade for d in decisions.values()}
    except ResidualPIIError:
        return Result("FAILED", processing_id, "RESIDUAL_CHECK_FAILED")
    except Exception:
        return Result("FAILED", processing_id, "PROCESSOR_ERROR")
    if "C" in grades:
        return Result("BLOCKED", processing_id, "CONFIDENTIAL", grade="C")
    if source.unsupported_format:
        return Result("FAILED", processing_id, "UNSUPPORTED_FEATURE")
    for key in source.output_formats:
        raw = decisions.get(key + ":raw")
        if raw is not None and raw.grade == "S" and decisions[key].text == source.display_texts[key]:
            return Result("FAILED", processing_id, "RESIDUAL_CHECK_FAILED")

    try:
        data, expected, changed = build_copy(source, decisions)
        copy = read_xlsx(data, "보호본.xlsx")
        values = {s.id: s.text for s in copy.segments if s.exportable}
        if values != expected or copy.comments or copy.hidden_sheets or copy.hidden_rows or copy.hidden_columns:
            return Result("FAILED", processing_id, "INVALID_COPY")
        if processor.verify(session_id, tuple(copy.segments)) is not True:
            return Result("FAILED", processing_id, "RESIDUAL_CHECK_FAILED")
    except Exception:
        return Result("FAILED", processing_id, "COPY_VERIFICATION_ERROR")

    summary = Summary(changed, source.comments, source.hidden_sheets, source.hidden_rows, source.hidden_columns)
    return Result("READY", processing_id, grade="S" if "S" in grades else "O", file_bytes=data, summary=summary)
