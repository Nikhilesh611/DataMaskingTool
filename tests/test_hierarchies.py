"""Tests for all three generalisation hierarchies."""

from __future__ import annotations

import pytest

from app.hierarchies.date_hierarchy import DateHierarchy
from app.hierarchies.icd10_hierarchy import ICD10Hierarchy
from app.hierarchies.zipcode_hierarchy import ZipCodeHierarchy


class TestDateHierarchy:
    def setup_method(self):
        self.h = DateHierarchy()

    def test_level0_returns_original(self):
        assert self.h.generalise("1985-07-23", 0) == "1985-07-23"

    def test_level1_month_year(self):
        assert self.h.generalise("1985-07-23", 1) == "1985-07"

    def test_level2_year(self):
        assert self.h.generalise("1985-07-23", 2) == "1985"

    def test_level3_decade(self):
        assert self.h.generalise("1985-07-23", 3) == "1980*"

    def test_level4_suppressed(self):
        assert self.h.generalise("1985-07-23", 4) == "*"

    def test_above_max_level_saturates(self):
        assert self.h.generalise("1985-07-23", 99) == "*"

    def test_bad_input_returns_redacted_above_level0(self):
        assert self.h.generalise("not-a-date", 1) == "[REDACTED]"

    def test_bad_input_at_level0_returns_original(self):
        assert self.h.generalise("not-a-date", 0) == "not-a-date"

    def test_max_level_is_4(self):
        assert self.h.max_level == 4


class TestZipCodeHierarchy:
    def setup_method(self):
        self.h = ZipCodeHierarchy()

    def test_level0_returns_original(self):
        assert self.h.generalise("10001", 0) == "10001"

    def test_level1_masks_one_char(self):
        assert self.h.generalise("10001", 1) == "1000*"

    def test_level2_masks_two_chars(self):
        assert self.h.generalise("10001", 2) == "100**"

    def test_level5_fully_masked(self):
        assert self.h.generalise("10001", 5) == "*****"

    def test_saturation_beyond_length(self):
        assert self.h.generalise("ABC", 10) == "***"

    def test_empty_string(self):
        assert self.h.generalise("", 1) == "*"

    def test_arbitrary_length_works(self):
        # UK-style postcode
        result = self.h.generalise("SW1A 2AA", 3)
        assert result.endswith("***")
        assert len(result) == len("SW1A 2AA")


class TestICD10Hierarchy:
    def setup_method(self):
        self.h = ICD10Hierarchy()

    def test_level0_returns_original(self):
        assert self.h.generalise("J18.9", 0) == "J18.9"

    def test_level1_three_char_category(self):
        assert self.h.generalise("J18.9", 1) == "J18"

    def test_level2_chapter_wildcard(self):
        assert self.h.generalise("J18.9", 2) == "J**"

    def test_level3_fully_suppressed(self):
        assert self.h.generalise("J18.9", 3) == "***"

    def test_above_max_level_saturates(self):
        assert self.h.generalise("J18.9", 99) == "***"

    def test_bad_input_returns_redacted(self):
        assert self.h.generalise("not-a-code", 1) == "[REDACTED]"

    def test_lowercase_accepted(self):
        result = self.h.generalise("j18.9", 1)
        assert result == "J18"

    def test_max_level_is_3(self):
        assert self.h.max_level == 3
