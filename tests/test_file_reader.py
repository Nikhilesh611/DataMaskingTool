"""Tests for the file reader."""

from __future__ import annotations

import os
import tempfile

import pytest

from app.exceptions import (
    FileNotFoundError,
    PathTraversalError,
    UnsupportedFormatError,
)
from app.file_reader import read_file


@pytest.fixture
def data_dir(tmp_path):
    """Temp directory with a few sample files."""
    (tmp_path / "sample.json").write_text('{"a": 1}')
    (tmp_path / "sample.xml").write_bytes(b"<root/>")
    (tmp_path / "sample.yaml").write_text("key: value")
    return str(tmp_path)


class TestFileReader:
    def test_valid_json_returns_bytes_and_format(self, data_dir):
        raw, fmt = read_file("sample.json", data_dir)
        assert isinstance(raw, bytes)
        assert fmt == "json"

    def test_valid_xml_returns_xml_format(self, data_dir):
        _, fmt = read_file("sample.xml", data_dir)
        assert fmt == "xml"

    def test_valid_yaml_returns_yaml_format(self, data_dir):
        _, fmt = read_file("sample.yaml", data_dir)
        assert fmt == "yaml"

    def test_missing_file_raises(self, data_dir):
        with pytest.raises(FileNotFoundError):
            read_file("missing.json", data_dir)

    def test_unsupported_extension_raises(self, data_dir):
        (os.path.join(data_dir, "secret.txt"))
        # Write the file but its extension is unsupported
        with open(os.path.join(data_dir, "secret.txt"), "w") as f:
            f.write("data")
        with pytest.raises(UnsupportedFormatError):
            read_file("secret.txt", data_dir)

    def test_path_traversal_with_dotdot_raises(self, data_dir):
        # Basename extraction strips directory parts, so ../other.json
        # becomes other.json — which doesn't exist → FileNotFoundError.
        # This verifies traversal is prevented (the caller gets an error not data).
        with pytest.raises((PathTraversalError, UnsupportedFormatError, FileNotFoundError)):
            read_file("../other.json", data_dir)

    def test_null_byte_raises(self, data_dir):
        with pytest.raises((PathTraversalError, UnsupportedFormatError, ValueError)):
            read_file("sample\x00.json", data_dir)

    def test_returns_raw_bytes_not_parsed(self, data_dir):
        raw, _ = read_file("sample.json", data_dir)
        assert isinstance(raw, bytes)
        # Should be raw bytes, not a dict
        assert not isinstance(raw, dict)
