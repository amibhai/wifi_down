"""Validates that wifi_auditor.__version__ is a non-dev string matching pyproject.toml."""
import re


def test_version_is_string():
    from wifi_auditor import __version__
    assert isinstance(__version__, str)
    assert __version__ != "0.0.0-dev"


def test_version_semver_format():
    from wifi_auditor import __version__
    assert re.match(r"^\d+\.\d+\.\d+", __version__), (
        f"__version__ {__version__!r} does not start with MAJOR.MINOR.PATCH"
    )


def test_version_matches_pyproject():
    """Ensure __version__ matches the version field in pyproject.toml."""
    import tomllib
    import pathlib

    pyproject = pathlib.Path(__file__).parent.parent / "pyproject.toml"
    with open(pyproject, "rb") as f:
        data = tomllib.load(f)
    toml_version = data["project"]["version"]

    from wifi_auditor import __version__
    assert __version__ == toml_version, (
        f"__version__ {__version__!r} != pyproject.toml version {toml_version!r}"
    )
