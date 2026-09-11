"""Unit tests for GroupMappingStore.

Covers:
  - Loading from a valid JSON file
  - Loading from an empty list
  - Multi-group priority resolution
  - Deterministic tie-breaking by file order
  - No matching group → None (fail closed)
  - CRUD operations (upsert, delete, get)
  - Save and reload round-trip
  - Invalid file content raises ValueError
  - Missing file raises FileNotFoundError
"""

from __future__ import annotations

import json
import os
import tempfile

import pytest

from app.idp.group_mapper import GroupMapping, GroupMappingStore


# ── Helpers ───────────────────────────────────────────────────────────────────

def _write_mappings(path: str, data: list[dict]) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh)


# ── Load tests ────────────────────────────────────────────────────────────────

class TestGroupMappingStoreLoad:
    def test_load_valid_file(self, tmp_path):
        f = tmp_path / "mappings.json"
        _write_mappings(str(f), [
            {"group": "data-analysts", "internal_role": "analyst", "priority": 10},
        ])
        store = GroupMappingStore()
        store.load(str(f))
        assert len(store.list_mappings()) == 1

    def test_load_empty_list(self, tmp_path):
        f = tmp_path / "mappings.json"
        _write_mappings(str(f), [])
        store = GroupMappingStore()
        store.load(str(f))
        assert store.list_mappings() == []

    def test_load_missing_file_raises(self):
        store = GroupMappingStore()
        with pytest.raises(FileNotFoundError, match="does not exist"):
            store.load("/nonexistent/path/mappings.json")

    def test_load_not_a_list_raises(self, tmp_path):
        f = tmp_path / "mappings.json"
        f.write_text('{"group": "bad"}')
        store = GroupMappingStore()
        with pytest.raises(ValueError, match="JSON array"):
            store.load(str(f))

    def test_load_invalid_json_raises(self, tmp_path):
        f = tmp_path / "mappings.json"
        f.write_text("not-json")
        store = GroupMappingStore()
        with pytest.raises(Exception):  # json.JSONDecodeError
            store.load(str(f))


# ── Resolution tests ──────────────────────────────────────────────────────────

class TestGroupMappingStoreResolve:
    @pytest.fixture
    def store_with_mappings(self, tmp_path):
        f = tmp_path / "mappings.json"
        _write_mappings(str(f), [
            {"group": "finance-team",  "internal_role": "auditor",  "priority": 10},
            {"group": "data-analysts", "internal_role": "analyst",  "priority": 20},
            {"group": "admin-users",   "internal_role": "operator", "priority": 1},
        ])
        store = GroupMappingStore()
        store.load(str(f))
        return store

    def test_single_group_match(self, store_with_mappings):
        role = store_with_mappings.resolve_role(["finance-team"])
        assert role == "auditor"

    def test_single_group_no_match_returns_none(self, store_with_mappings):
        role = store_with_mappings.resolve_role(["unknown-group"])
        assert role is None  # fail closed: no mapping = no access

    def test_empty_groups_returns_none(self, store_with_mappings):
        role = store_with_mappings.resolve_role([])
        assert role is None

    def test_multi_group_priority_wins(self, store_with_mappings):
        """admin-users (priority=1) beats finance-team (priority=10)."""
        role = store_with_mappings.resolve_role(["finance-team", "admin-users"])
        assert role == "operator"

    def test_multi_group_lower_priority_number_wins(self, store_with_mappings):
        """data-analysts (priority=20) loses to finance-team (priority=10)."""
        role = store_with_mappings.resolve_role(["data-analysts", "finance-team"])
        assert role == "auditor"

    def test_multi_group_only_one_mapped(self, store_with_mappings):
        """One group is mapped, the other is not — returns the mapped one."""
        role = store_with_mappings.resolve_role(["data-analysts", "unknown-group"])
        assert role == "analyst"

    def test_multi_group_none_mapped_returns_none(self, store_with_mappings):
        role = store_with_mappings.resolve_role(["unknown-a", "unknown-b"])
        assert role is None

    def test_tie_broken_by_file_order(self, tmp_path):
        """Two mappings with same priority: first in file order wins."""
        f = tmp_path / "mappings.json"
        _write_mappings(str(f), [
            {"group": "group-a", "internal_role": "analyst",  "priority": 5},
            {"group": "group-b", "internal_role": "auditor",  "priority": 5},
        ])
        store = GroupMappingStore()
        store.load(str(f))
        # group-a appears first in file with same priority → wins
        role = store.resolve_role(["group-b", "group-a"])
        assert role == "analyst"

    def test_resolution_not_affected_by_jwt_claim_order(self, store_with_mappings):
        """Priority ordering is independent of the order groups appear in the JWT."""
        order1 = store_with_mappings.resolve_role(["data-analysts", "admin-users"])
        order2 = store_with_mappings.resolve_role(["admin-users", "data-analysts"])
        assert order1 == order2 == "operator"


# ── CRUD tests ────────────────────────────────────────────────────────────────

class TestGroupMappingStoreCRUD:
    @pytest.fixture
    def store(self, tmp_path):
        f = tmp_path / "mappings.json"
        _write_mappings(str(f), [
            {"group": "finance-team", "internal_role": "auditor", "priority": 10},
        ])
        s = GroupMappingStore()
        s.load(str(f))
        return s, str(f)

    def test_upsert_new_mapping(self, store):
        s, _ = store
        s.upsert(GroupMapping(group="hr-team", internal_role="analyst", priority=20))
        assert s.get("hr-team") is not None
        assert s.get("hr-team").internal_role == "analyst"

    def test_upsert_updates_existing(self, store):
        s, _ = store
        s.upsert(GroupMapping(group="finance-team", internal_role="analyst", priority=5))
        assert s.get("finance-team").internal_role == "analyst"
        assert s.get("finance-team").priority == 5

    def test_delete_existing(self, store):
        s, _ = store
        deleted = s.delete("finance-team")
        assert deleted is True
        assert s.get("finance-team") is None
        assert s.resolve_role(["finance-team"]) is None

    def test_delete_nonexistent_returns_false(self, store):
        s, _ = store
        deleted = s.delete("nonexistent-group")
        assert deleted is False

    def test_save_and_reload(self, store, tmp_path):
        s, path = store
        s.upsert(GroupMapping(group="new-team", internal_role="analyst", priority=1))
        s.save(path)

        s2 = GroupMappingStore()
        s2.load(path)
        assert s2.get("new-team") is not None
        assert s2.resolve_role(["new-team"]) == "analyst"


# ── GroupMapping model validation ─────────────────────────────────────────────

class TestGroupMappingModel:
    def test_empty_group_raises(self):
        with pytest.raises(ValueError, match="group"):
            GroupMapping(group="", internal_role="analyst")

    def test_empty_role_raises(self):
        with pytest.raises(ValueError, match="internal_role"):
            GroupMapping(group="some-group", internal_role="")

    def test_negative_priority_raises(self):
        with pytest.raises(ValueError, match="priority"):
            GroupMapping(group="some-group", internal_role="analyst", priority=-1)

    def test_default_priority_is_zero(self):
        m = GroupMapping(group="g", internal_role="analyst")
        assert m.priority == 0
