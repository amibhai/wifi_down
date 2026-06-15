"""Validates schema and structure of data/router_defaults.yaml."""
import pathlib

import yaml

YAML_PATH = pathlib.Path(__file__).parent.parent / "data" / "router_defaults.yaml"


def test_yaml_loads():
    data = yaml.safe_load(YAML_PATH.read_text())
    assert data is not None


def test_schema_version_present():
    data = yaml.safe_load(YAML_PATH.read_text())
    assert "schema_version" in data, "schema_version key missing from top level"
    assert isinstance(data["schema_version"], int)


def test_last_updated_present():
    data = yaml.safe_load(YAML_PATH.read_text())
    assert "last_updated" in data, "last_updated key missing from top level"


def test_vendor_defaults_section_exists():
    data = yaml.safe_load(YAML_PATH.read_text())
    assert "vendor_defaults" in data, "vendor_defaults section missing"
    assert isinstance(data["vendor_defaults"], dict)


def test_vendor_entries_have_passwords():
    data = yaml.safe_load(YAML_PATH.read_text())
    vendors = data.get("vendor_defaults", {})
    for vendor, entry in vendors.items():
        assert "passwords" in entry, (
            f"Vendor '{vendor}' missing 'passwords' list"
        )
        assert isinstance(entry["passwords"], list), (
            f"Vendor '{vendor}' passwords must be a list"
        )
        assert len(entry["passwords"]) > 0, (
            f"Vendor '{vendor}' has empty passwords list"
        )
