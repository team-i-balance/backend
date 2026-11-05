"""Validate the restricted, values-only XLSX format before openpyxl normalizes it."""

from io import BytesIO
from posixpath import dirname, join, normpath
from re import compile as compile_pattern
from zipfile import ZipFile

from defusedxml.ElementTree import fromstring
from openpyxl.utils.cell import column_index_from_string, coordinate_from_string, coordinate_to_tuple

MAX_UPLOAD = 8 * 1024 * 1024
MAX_EXPANDED = 24 * 1024 * 1024
MAX_GRID = 100_000
MAX_PARTS = 256
SHEET = compile_pattern(r"xl/worksheets/sheet\d+\.xml")
COMMENTS = compile_pattern(r"xl/(comments/)?comments?\d+\.xml")
SHARED_STRINGS = "xl/sharedStrings.xml"
STRING_TABLE_TYPE = "application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml"
ALLOWED_PART = compile_pattern(
    r"\[Content_Types\]\.xml|_rels/\.rels|docProps/(core|app|custom)\.xml|"
    r"xl/(workbook|styles|sharedStrings)\.xml|xl/_rels/workbook\.xml\.rels|"
    r"xl/theme/theme\d+\.xml|xl/worksheets/sheet\d+\.xml|"
    r"xl/worksheets/_rels/sheet\d+\.xml\.rels|xl/(comments/)?comment[s]?\d+\.xml|"
    r"xl/drawings/(commentsDrawing|vmlDrawing)\d+\.vml"
)
UNSUPPORTED_TAGS = {
    "f", "formula", "formula1", "formula2", "oleObjects", "controls", "drawing",
    "picture", "tableParts", "hyperlinks", "mergeCells", "definedName", "extLst",
    "AlternateContent", "conditionalFormatting", "dataValidations", "headerFooter",
    "autoFilter", "externalReferences", "sheetProtection",
}
WORKBOOK_TYPE = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"
TEMPLATE_TYPE = "application/vnd.openxmlformats-officedocument.spreadsheetml.template.main+xml"
MAIN = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"
REL = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
PKG_REL = "{http://schemas.openxmlformats.org/package/2006/relationships}"
CUSTOM_PROPERTIES = "{http://schemas.openxmlformats.org/officeDocument/2006/custom-properties}Properties"
CALC_EXTENSION = "{7626C862-2A13-11E5-B345-FEFF819CDC9F}"
HEADER_FOOTER_FIELDS = {MAIN + position + part for position in ("odd", "even", "first")
                        for part in ("Header", "Footer")}
BOOL_VALUES = {"true", "false", "1", "0"}


class RejectedFile(ValueError):
    """A non-sensitive error code, safe to return to the caller."""


def local_name(tag):
    return tag.rsplit("}", 1)[-1]


def validate_boolean_formula(cell, formula):
    """Calc stores literal booleans as TRUE()/FALSE() with a cached boolean value."""
    value = cell.find(MAIN + "v")
    expression = (formula.text or "").strip().upper()
    literals = {"TRUE()": "1", "FALSE()": "0"}
    if (cell.get("t") != "b" or expression not in literals or len(formula)
            or set(formula.attrib) - {"aca", "t"} or formula.get("t", "normal") != "normal"
            or formula.get("aca", "false") not in BOOL_VALUES):
        raise RejectedFile("UNSUPPORTED_FEATURE")
    if (value is None or list(cell) != [formula, value] or len(value) or value.attrib
            or value.text != literals[expression] or any((s or "").strip() for s in (cell.text, formula.tail, value.tail))):
        raise RejectedFile("INVALID_XLSX")


def empty_header_footer(node):
    flags = {"differentOddEven", "differentFirst", "scaleWithDoc", "alignWithMargins"}
    return (node.tag == MAIN + "headerFooter" and not any(s.strip() for s in node.itertext())
            and all(k in flags and v in BOOL_VALUES for k, v in node.attrib.items())
            and all(n.tag in HEADER_FOOTER_FIELDS and not n.attrib and not len(n) for n in node))


def calc_settings_only(node):
    if node.tag != MAIN + "extLst" or node.attrib or any(s.strip() for s in node.itertext()):
        return False
    for extension in node:
        if (extension.tag != MAIN + "ext" or extension.attrib != {"uri": CALC_EXTENSION}
                or len(extension) != 1):
            return False
        settings = extension[0]
        if (settings.tag != "{http://schemas.libreoffice.org/}extCalcPr" or len(settings)
                or settings.attrib != {"stringRefSyntax": "ExcelA1"}):
            return False
    return True


def table_index(text, count):
    digits = (text or "").strip().removeprefix("+")
    if not digits.isascii() or not digits.isdecimal() or int(digits) >= count:
        raise RejectedFile("INVALID_XLSX")


def only_child(parent, tag):
    children = parent.findall(MAIN + tag)
    if len(children) != 1:
        raise RejectedFile("INVALID_XLSX")
    return children[0]


def no_loose_text(node):
    if (node.text or "").strip() or any((child.tail or "").strip() for child in node):
        raise RejectedFile("INVALID_XLSX")


def inspect_text(node):
    """Accept plain text or ordered rich runs, never a value the reader would overwrite."""
    no_loose_text(node)
    plain = node.findall(MAIN + "t")
    if plain:
        if len(node) != 1 or len(plain[0]):
            raise RejectedFile("INVALID_XLSX")
        return
    for run in node:
        if run.tag != MAIN + "r":
            # Phonetic annotations, for example, are not part of openpyxl's plain text.
            raise RejectedFile("UNSUPPORTED_FEATURE")
        no_loose_text(run)
        text = only_child(run, "t")
        if len(text) or [child.tag for child in run] not in (
                [MAIN + "t"], [MAIN + "rPr", MAIN + "t"]):
            raise RejectedFile("INVALID_XLSX")
        if len(run) == 2 and any(s.strip() for s in run[0].itertext()):
            raise RejectedFile("UNSUPPORTED_FEATURE")


def inspect_cell_payload(cell, string_count):
    values = cell.findall(MAIN + "v")
    inlines = cell.findall(MAIN + "is")
    kind = cell.get("t", "n")
    if kind not in {"n", "s", "str", "inlineStr", "d", "b", "e"}:
        raise RejectedFile("INVALID_XLSX")
    no_loose_text(cell)
    if any(child.tag not in {MAIN + "v", MAIN + "is", MAIN + "f"} for child in cell):
        raise RejectedFile("UNSUPPORTED_FEATURE")
    if len(values) + len(inlines) > 1:
        raise RejectedFile("INVALID_XLSX")
    if (inlines and kind != "inlineStr") or (values and (kind == "inlineStr" or len(values[0]))):
        raise RejectedFile("INVALID_XLSX")
    if kind == "s":
        table_index(values[0].text if values else None, string_count)
    if kind == "b" and (not values or values[0].text not in {"0", "1"}):
        raise RejectedFile("INVALID_XLSX")
    if inlines:
        inspect_text(inlines[0])


def inspect_comments(root):
    lists = root.findall(MAIN + "commentList")
    authors = root.findall(MAIN + "authors")
    if root.tag != MAIN + "comments" or len(lists) != 1 or len(authors) != 1:
        raise RejectedFile("INVALID_XLSX")
    author_count = len(authors[0].findall(MAIN + "author"))
    seen = set()
    for comment in lists[0]:
        if comment.tag != MAIN + "comment":
            raise RejectedFile("INVALID_XLSX")
        letters, row = coordinate_from_string(comment.attrib["ref"])
        column = column_index_from_string(letters)
        if row > 1048576 or column > 16384 or (row, column) in seen:
            raise RejectedFile("INVALID_XLSX")
        seen.add((row, column))
        table_index(comment.get("authorId"), author_count)
        inspect_text(only_child(comment, "text"))


def inspect_sheet(root, string_count):
    if root.tag != MAIN + "worksheet":
        raise RejectedFile("INVALID_XLSX")
    max_row = max_column = 0
    seen = set()
    numeric_serials = {}
    verified_formulas = set()
    sheet_data = only_child(root, "sheetData")
    checked_rows = set()
    row_number = 0
    for row_node in sheet_data:
        if row_node.tag != MAIN + "row":
            raise RejectedFile("INVALID_XLSX")
        row_number = int(row_node.get("r", row_number + 1))
        if not 1 <= row_number <= 1048576 or row_number in checked_rows:
            raise RejectedFile("INVALID_XLSX")
        checked_rows.add(row_number)
        for cell in row_node:
            if cell.tag != MAIN + "c":
                raise RejectedFile("INVALID_XLSX")
            row, column = coordinate_to_tuple(cell.attrib["r"])
            if row != row_number or not 1 <= column <= 16384 or (row, column) in seen:
                raise RejectedFile("INVALID_XLSX")
            seen.add((row, column))
            max_row, max_column = max(max_row, row), max(max_column, column)
            if max_row * max_column > MAX_GRID:
                raise RejectedFile("FILE_TOO_LARGE")
            inspect_cell_payload(cell, string_count)
            # Compare format conditions against the stored serial, before time rounding.
            raw = cell.findtext(MAIN + "v")
            if cell.get("t", "n") == "n" and raw:
                numeric_serials[row, column] = raw
            formula = cell.find(MAIN + "f")
            if formula is not None:
                validate_boolean_formula(cell, formula)
                verified_formulas.add(formula)
    cell_count = row_count = 0
    for node in root.iter():
        tag = local_name(node.tag)
        cell_count += tag == "c"
        row_count += tag == "row"
        if node in verified_formulas or (tag == "headerFooter" and empty_header_footer(node)):
            continue
        if tag in UNSUPPORTED_TAGS:
            raise RejectedFile("UNSUPPORTED_FEATURE")
        if tag == "sheetFormatPr":
            if (node.get("zeroHeight") in {"1", "true"} or float(node.get("defaultColWidth", 1)) == 0
                    or float(node.get("defaultRowHeight", 1)) == 0):
                raise RejectedFile("UNSUPPORTED_FEATURE")
    if cell_count != len(seen) or row_count != len(checked_rows):
        raise RejectedFile("INVALID_XLSX")
    return max_row * max_column, numeric_serials


def inspect_workbook(root):
    if root.tag != MAIN + "workbook":
        raise RejectedFile("INVALID_XLSX")
    sheets = only_child(root, "sheets")
    names, ids = set(), set()
    links = []
    for sheet in sheets:
        if sheet.tag != MAIN + "sheet":
            raise RejectedFile("INVALID_XLSX")
        name = sheet.attrib["name"].casefold()
        digits = sheet.attrib["sheetId"]
        if not name or not digits.isascii() or not digits.isdecimal():
            raise RejectedFile("INVALID_XLSX")
        sheet_id = int(digits)
        if not 1 <= sheet_id <= 0xffffffff or name in names or sheet_id in ids:
            raise RejectedFile("INVALID_XLSX")
        names.add(name)
        ids.add(sheet_id)
        links.append(sheet.attrib["{" + REL + "}id"])
    if not links or len(set(links)) != len(links):
        raise RejectedFile("INVALID_XLSX")
    if sum(1 for _ in root.iter(MAIN + "sheet")) != len(links):
        raise RejectedFile("INVALID_XLSX")
    extension_lists = set(root.findall(MAIN + "extLst"))
    for node in root.iter():
        if node in extension_lists and calc_settings_only(node):
            continue
        if local_name(node.tag) in UNSUPPORTED_TAGS:
            raise RejectedFile("UNSUPPORTED_FEATURE")
    return links


def inspect_links(root, name, names):
    if root.tag != PKG_REL + "Relationships":
        raise RejectedFile("INVALID_XLSX")
    links = {}
    part_dir = dirname(dirname(name))
    for rel in root:
        rel_id = rel.get("Id")
        if rel.tag != PKG_REL + "Relationship" or not rel_id or rel_id in links:
            raise RejectedFile("INVALID_XLSX")
        if rel.get("TargetMode", "Internal") != "Internal":
            raise RejectedFile("UNSUPPORTED_FEATURE")
        target = normpath(join(part_dir, rel.attrib["Target"])).lstrip("/")
        if target not in names:
            raise RejectedFile("INVALID_XLSX")
        links[rel_id] = rel.attrib["Type"], target
    return links


def inspect_package(data):
    if len(data) > MAX_UPLOAD:
        raise RejectedFile("FILE_TOO_LARGE")
    with ZipFile(BytesIO(data)) as package:
        files = [info for info in package.infolist() if not info.is_dir()]
        if len(files) > MAX_PARTS or sum(f.file_size for f in files) > MAX_EXPANDED:
            raise RejectedFile("FILE_TOO_LARGE")
        names = {f.filename for f in files}
        required = {"[Content_Types].xml", "_rels/.rels", "xl/workbook.xml", "xl/_rels/workbook.xml.rels"}
        if len(names) != len(files) or not required.issubset(names):
            raise RejectedFile("INVALID_XLSX")
        metadata = {}
        grid_size = 0
        sheet_ids = []
        workbook_links = {}
        serials_by_part = {}
        comment_targets = set()
        string_count = 0
        if SHARED_STRINGS in names:
            strings = fromstring(package.read(SHARED_STRINGS), forbid_dtd=True)
            if strings.tag != MAIN + "sst":
                raise RejectedFile("INVALID_XLSX")
            for item in strings:
                if item.tag != MAIN + "si":
                    raise RejectedFile("UNSUPPORTED_FEATURE")
                inspect_text(item)
                string_count += 1
            del strings
        for info in files:
            name = info.filename
            if not ALLOWED_PART.fullmatch(name) or info.flag_bits & 1:
                raise RejectedFile("UNSUPPORTED_FEATURE")
            if name == SHARED_STRINGS:
                continue  # Already parsed, regardless of ZIP member order.
            root = fromstring(package.read(info), forbid_dtd=True)
            if name == "[Content_Types].xml":
                # Effective type per part (OPC: an Override wins, else the Default for the
                # extension). Generators such as the Open XML SDK declare the workbook only
                # through <Default Extension="xml" ContentType=workbook>.
                overrides = {n.get("PartName"): n.get("ContentType") for n in root if local_name(n.tag) == "Override"}
                defaults = {(n.get("Extension") or "").lower(): n.get("ContentType")
                            for n in root if local_name(n.tag) == "Default"}
                workbook_parts = sorted(
                    "/" + part for part in names
                    if part != "[Content_Types].xml"  # the type map itself is not a part
                    and overrides.get("/" + part, defaults.get(part.rsplit(".", 1)[-1].lower())) == WORKBOOK_TYPE
                )
                if workbook_parts != ["/xl/workbook.xml"]:
                    raise RejectedFile("UNSUPPORTED_FEATURE")
                string_tables = [n.get("PartName") for n in root if n.get("ContentType") == STRING_TABLE_TYPE]
                if string_tables != (["/" + SHARED_STRINGS] if SHARED_STRINGS in names else []):
                    raise RejectedFile("INVALID_XLSX")
                types = [n.get("ContentType", "").lower() for n in root]
                if any(t == TEMPLATE_TYPE or "macro" in t or "oleobject" in t for t in types):
                    raise RejectedFile("UNSUPPORTED_FEATURE")
            elif name.endswith(".rels"):
                links = inspect_links(root, name, names)
                if name == "_rels/.rels":
                    documents = [target for kind, target in links.values() if kind == REL + "/officeDocument"]
                    if documents != ["xl/workbook.xml"]:
                        raise RejectedFile("INVALID_XLSX")
                elif name == "xl/_rels/workbook.xml.rels":
                    workbook_links = links
                else:
                    sheet_part = name.replace("/_rels/", "/").removesuffix(".rels")
                    if sheet_part not in names:
                        raise RejectedFile("INVALID_XLSX")
                    notes = [target for kind, target in links.values() if kind == REL + "/comments"]
                    if len(notes) > 1 or any(not COMMENTS.fullmatch(t) or t in comment_targets for t in notes):
                        raise RejectedFile("INVALID_XLSX")
                    comment_targets.update(notes)
            elif SHEET.fullmatch(name):
                sheet_size, serials_by_part[name] = inspect_sheet(root, string_count)
                grid_size += sheet_size
                if grid_size > MAX_GRID:
                    raise RejectedFile("FILE_TOO_LARGE")
            elif name == "xl/workbook.xml":
                sheet_ids = inspect_workbook(root)
            elif name == "xl/styles.xml":
                # Include unused formats and formats on empty/hidden cells too.
                seen_formats = set()
                for index, node in enumerate(root.iter(MAIN + "numFmt")):
                    number = int(node.attrib["numFmtId"])
                    if number in seen_formats:
                        raise RejectedFile("INVALID_XLSX")
                    seen_formats.add(number)
                    metadata[f"number-format:{index}"] = node.attrib["formatCode"]
            elif COMMENTS.fullmatch(name):
                inspect_comments(root)
            elif name.endswith(".vml"):
                # Excel uses VML for ordinary notes as well as legacy form controls.
                for shape in (n for n in root.iter() if local_name(n.tag) == "shape"):
                    if not any(local_name(n.tag) == "ClientData" and n.get("ObjectType") == "Note"
                               for n in shape.iter()):
                        raise RejectedFile("UNSUPPORTED_FEATURE")
            elif name == "docProps/custom.xml":
                if root.tag != CUSTOM_PROPERTIES or len(root) or root.attrib or (root.text or "").strip():
                    raise RejectedFile("UNSUPPORTED_FEATURE")
            elif name.startswith("docProps/"):
                for index, node in enumerate(root.iter()):
                    if node.text and node.text.strip():
                        metadata[f"{name}:{index}:{local_name(node.tag)}"] = node.text
        # Every sheet the reader can open must have passed the raw worksheet checks.
        targets = []
        for link in sheet_ids:
            kind, target = workbook_links.get(link, (None, ""))
            if kind != REL + "/worksheet" or target not in serials_by_part:
                raise RejectedFile("INVALID_XLSX")
            targets.append(target)
        if len(set(targets)) != len(targets) or set(targets) != set(serials_by_part):
            raise RejectedFile("INVALID_XLSX")
        if comment_targets != {name for name in names if COMMENTS.fullmatch(name)}:
            raise RejectedFile("INVALID_XLSX")
        return metadata, [serials_by_part[target] for target in targets]
