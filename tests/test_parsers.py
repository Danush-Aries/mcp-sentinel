from __future__ import annotations

import pytest

from mcp_sentinel.engine import InputError, load_target


def test_settings_loader_basic(fx):
    t = load_target(fx("clean_settings.json"))
    assert t.kind == "settings"
    assert len(t.servers) == 1
    s = t.servers[0]
    assert s.name == "weather"
    assert s.command == "npx"
    assert s.env.get("LOG_LEVEL") == "info"
    assert [tool.name for tool in s.tools] == ["get_weather"]


def test_manifest_loader_basic(fx):
    t = load_target(fx("manifest_min.json"))
    assert t.kind == "manifest"
    assert len(t.servers) == 1
    assert t.servers[0].name == "file-manager"
    assert {tool.name for tool in t.servers[0].tools} == {"list_files", "delete_file"}


def test_input_autodetect(fx):
    assert load_target(fx("clean_settings.json"), "auto").kind == "settings"
    assert load_target(fx("manifest_min.json"), "auto").kind == "manifest"


def test_loader_bad_json_errors(fx):
    with pytest.raises(InputError):
        load_target(fx("malformed.json"))
    with pytest.raises(InputError):
        load_target("/no/such/file.json")


def test_optional_tools_absent(fx):
    t = load_target(fx("unpinned_npx.json"))
    assert all(s.tools == [] for s in t.servers)


def test_forced_kind_and_unknown(fx):
    assert load_target(fx("manifest_min.json"), "manifest").kind == "manifest"
    with pytest.raises(InputError):
        load_target(fx("clean_settings.json"), "bogus")
