# Contributing to wifi_down

Thanks for your interest. Here is how to get a working dev environment and
submit changes.

## Dev Setup

```bash
git clone https://github.com/amibhai/wifi_down.git
cd wifi_down
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

## Running the Test Suite

```bash
pytest tests/ -v
```

## Linting and Type Checking

```bash
ruff check .
mypy modules/ wifi_auditor/ --ignore-missing-imports
```

All three must pass before a PR is opened. The CI workflow enforces this.

## Branch Naming

| Type     | Pattern               |
|----------|-----------------------|
| Feature  | `feat/short-description` |
| Bug fix  | `fix/short-description`  |
| Docs     | `docs/short-description` |

## Commit Messages

Use imperative mood: `Add WPS Pixie-Dust timeout` not `Added` or `Adding`.
One logical change per commit.

## Pull Request Checklist

- [ ] Tests pass locally (`pytest tests/ -v`)
- [ ] No ruff lint errors (`ruff check .`)
- [ ] New features have at least one test
- [ ] CHANGELOG.md updated under `[Unreleased]`
- [ ] `scope.yaml` is NOT committed (it is gitignored)

## Adding a New Attack Module

1. Create `modules/your_module.py`
2. Wire it into `wifi_auditor/cli.py` with a new menu key and action function
3. Add scope enforcement via `modules/scope.py` if the module does injection
4. Add at least one test in `tests/test_your_module.py`
5. Document it in README.md under the Features table

## Reporting Bugs

Open a GitHub issue with:
- OS and Python version
- Exact command that failed
- Full error output
- Wireless adapter model and chipset
