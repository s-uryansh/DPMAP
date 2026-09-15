import csv
import io
import os
from pathlib import Path
import struct
from types import SimpleNamespace
from zipfile import ZipFile

import pytest
from openpyxl import Workbook

from dpmap.engine.scanners import directory


def _error_code(action) -> str:
    with pytest.raises(directory.DirectoryScanError) as error:
        action()
    return error.value.code


def test_directory_root_validation(tmp_path, monkeypatch) -> None:
    root = tmp_path / "root"
    root.mkdir()
    target = root / "target"
    target.mkdir()
    file_target = root / "file.txt"
    file_target.write_text("test")
    linked = root / "linked"
    linked.symlink_to(target, target_is_directory=True)

    assert _error_code(lambda: directory.configured_roots(None)) == (
        "scan_roots_not_configured"
    )
    assert _error_code(
        lambda: directory.configured_roots(str(root / "missing"))
    ) == "invalid_scan_root"
    assert _error_code(lambda: directory.configured_roots(os.pathsep)) == (
        "invalid_scan_root"
    )
    assert _error_code(lambda: directory.configured_roots(str(file_target))) == (
        "invalid_scan_root"
    )
    roots = directory.configured_roots(str(root))
    assert directory.validate_directory(str(target), roots) == target
    assert _error_code(lambda: directory.validate_directory("relative", roots)) == (
        "invalid_path"
    )
    assert _error_code(
        lambda: directory.validate_directory(str(tmp_path), roots)
    ) == "path_not_allowed"
    assert _error_code(
        lambda: directory.validate_directory(str(linked), roots)
    ) == "symlink_target"
    assert _error_code(
        lambda: directory.validate_directory(str(root / "missing"), roots)
    ) == "path_not_found"
    assert _error_code(
        lambda: directory.validate_directory(str(file_target), roots)
    ) == "not_a_directory"

    original_resolve = Path.resolve
    unavailable = root / "unavailable"
    unavailable.mkdir()

    def unavailable_resolve(path, *args, **kwargs):
        if path == unavailable:
            raise PermissionError
        return original_resolve(path, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(Path, "resolve", unavailable_resolve)
        assert _error_code(
            lambda: directory.validate_directory(str(unavailable), roots)
        ) == "path_unavailable"
    with monkeypatch.context() as patch:
        patch.setattr(directory.os, "access", lambda *_: False)
        assert _error_code(
            lambda: directory.validate_directory(str(target), roots)
        ) == "permission_denied"

    assert directory._confidence_band(0.99) == "high"
    assert directory._confidence_band(0.85) == "medium"
    assert directory._confidence_band(0.1) == "low"


def test_file_reader_fallbacks_and_limits(tmp_path, monkeypatch) -> None:
    cp1252 = tmp_path / "legacy.txt"
    cp1252.write_bytes(b"note \x96 audit@example.in")
    result = directory._scan_file(cp1252, frozenset({"email"}))
    assert result.scanned
    assert result.warnings == ("encoding_fallback_cp1252",)

    empty_csv = tmp_path / "empty.csv"
    empty_csv.write_text("")
    assert directory._scan_file(empty_csv, frozenset({"email"})).scanned

    legacy_csv = tmp_path / "legacy.csv"
    legacy_csv.write_bytes(
        b"email,comment\naudit@example.in,Jos\xe9\naudit@example.in,ok\n"
    )
    result = directory._scan_file(legacy_csv, frozenset({"email"}))
    assert result.warnings == ("encoding_fallback_cp1252",)
    assert result.items[0].match_count == 2
    assert result.items[0].units_with_pii == 2

    fallback_csv = tmp_path / "fallback.csv"
    fallback_csv.write_text("audit@example.in\n")
    with monkeypatch.context() as patch:
        patch.setattr(
            csv.Sniffer,
            "sniff",
            lambda *_: (_ for _ in ()).throw(csv.Error()),
        )
        patch.setattr(csv.Sniffer, "has_header", lambda *_: False)
        assert directory._scan_file(
            fallback_csv, frozenset({"email"})
        ).scanned
    with monkeypatch.context() as patch:
        patch.setattr(csv.Sniffer, "sniff", lambda *_: csv.excel)
        patch.setattr(
            csv.Sniffer,
            "has_header",
            lambda *_: (_ for _ in ()).throw(csv.Error()),
        )
        assert directory._scan_file(
            fallback_csv, frozenset({"email"})
        ).scanned

    source = io.StringIO("header,value")
    with monkeypatch.context() as patch:
        patch.setattr(Path, "open", lambda *_args, **_kwargs: source)
        patch.setattr(csv.Sniffer, "sniff", lambda *_: csv.excel)
        patch.setattr(
            csv.Sniffer,
            "has_header",
            lambda *_: (_ for _ in ()).throw(RuntimeError()),
        )
        with pytest.raises(RuntimeError):
            directory._csv_reader(fallback_csv, "utf-8")
    assert source.closed

    workbook_path = tmp_path / "limits.xlsx"
    workbook = Workbook()
    workbook.active.append([None, "audit@example.in"])
    workbook.save(workbook_path)
    workbook.close()
    assert directory._scan_file(
        workbook_path, frozenset({"email"})
    ).items[0].match_count == 1

    with monkeypatch.context() as patch:
        patch.setattr(directory, "MAX_FILE_BYTES", 0)
        assert directory._scan_file(
            workbook_path, frozenset({"email"})
        ).warnings == ("file_too_large",)
    with monkeypatch.context() as patch:
        patch.setattr(directory, "MAX_XLSX_ENTRIES", 0)
        assert directory._scan_file(
            workbook_path, frozenset({"email"})
        ).warnings == ("xlsx_too_many_entries",)
    with monkeypatch.context() as patch:
        patch.setattr(directory, "MAX_XLSX_UNCOMPRESSED_BYTES", 0)
        assert directory._scan_file(
            workbook_path, frozenset({"email"})
        ).warnings == ("xlsx_too_large",)
    with monkeypatch.context() as patch:
        patch.setattr(directory, "MAX_CSV_FIELD_CHARS", 1)
        assert directory._scan_file(
            workbook_path, frozenset({"email"})
        ).warnings == ("xlsx_cell_too_large",)


def test_traversal_surfaces_directory_and_entry_errors(tmp_path, monkeypatch) -> None:
    blocked = tmp_path / "blocked"
    blocked.mkdir()
    original_scandir = os.scandir

    def controlled_scandir(path):
        if Path(path) == blocked:
            raise PermissionError
        return original_scandir(path)

    with monkeypatch.context() as patch:
        patch.setattr(directory.os, "scandir", controlled_scandir)
        results = list(directory.scan_directory(tmp_path, {"email"}))
    assert any(result.warnings == ("directory_unreadable",) for result in results)

    class BrokenEntry:
        name = "broken"
        path = str(tmp_path / "broken")

        def is_symlink(self):
            raise PermissionError

    class SpecialEntry:
        name = "special"
        path = str(tmp_path / "special")

        def is_symlink(self):
            return False

        def is_dir(self, *, follow_symlinks):
            return False

        def is_file(self, *, follow_symlinks):
            return False

    with monkeypatch.context() as patch:
        patch.setattr(
            directory.os, "scandir", lambda _: [BrokenEntry(), SpecialEntry()]
        )
        results = list(directory.scan_directory(tmp_path, {"email"}))
    assert [result.warnings for result in results] == [("path_unreadable",)]


def test_traversal_rejects_symlinks_without_following_them(tmp_path) -> None:
    target = tmp_path / "target.txt"
    target.write_text("linked@example.in")
    link = tmp_path / "linked.txt"
    link.symlink_to(target)

    results = {result.path.name: result for result in directory.scan_directory(
        tmp_path, {"email"}
    )}

    assert results["linked.txt"].warnings == ("symlink_skipped",)
    assert not results["linked.txt"].scanned
    assert not results["linked.txt"].items
    assert results["target.txt"].scanned


def test_unreadable_and_mutating_files_are_coverage_warnings(
    tmp_path, monkeypatch
) -> None:
    denied = tmp_path / "denied.txt"
    denied.write_text("denied@example.in")
    original_open = Path.open

    def controlled_open(path, *args, **kwargs):
        if path == denied:
            raise PermissionError
        return original_open(path, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(Path, "open", controlled_open)
        result = directory._scan_file(denied, frozenset({"email"}))
    assert result.warnings == ("file_unreadable",)
    assert not result.scanned

    unstable = tmp_path / "unstable.txt"
    unstable.write_text("no findings")
    original_stat = Path.stat
    calls = 0

    def changing_stat(path, *args, **kwargs):
        nonlocal calls
        value = original_stat(path, *args, **kwargs)
        if path != unstable:
            return value
        calls += 1
        if calls == 1:
            return value
        return SimpleNamespace(
            st_size=value.st_size,
            st_mtime_ns=value.st_mtime_ns + 1,
        )

    with monkeypatch.context() as patch:
        patch.setattr(Path, "stat", changing_stat)
        result = directory._scan_file(unstable, frozenset({"email"}))
    assert result.scanned
    assert result.warnings == ("unstable_file",)


def test_xlsx_archive_rejects_malicious_shapes(tmp_path) -> None:
    too_many = tmp_path / "too-many-entries.xlsx"
    with ZipFile(too_many, "w") as archive:
        for index in range(directory.MAX_XLSX_ENTRIES + 1):
            archive.writestr(f"entries/{index}", b"")
    assert directory._scan_file(
        too_many, frozenset({"email"})
    ).warnings == ("xlsx_too_many_entries",)

    oversized = tmp_path / "oversized-expansion.xlsx"
    with ZipFile(oversized, "w") as archive:
        archive.writestr("xl/worksheets/sheet1.xml", b"x")
    payload = bytearray(oversized.read_bytes())
    central_directory = payload.index(b"PK\x01\x02")
    struct.pack_into(
        "<I",
        payload,
        central_directory + 24,
        directory.MAX_XLSX_UNCOMPRESSED_BYTES + 1,
    )
    oversized.write_bytes(payload)
    assert directory._scan_file(
        oversized, frozenset({"email"})
    ).warnings == ("xlsx_too_large",)
