# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Python 3.13 project using Poetry for dependency management. The project uses Nix flakes for reproducible development environments.

## Development Environment

The project uses direnv with Nix flakes. Enter the development shell automatically via direnv or manually with `nix develop`.

## Common Commands

**Formatting:**
```bash
format  # runs ruff format and isort on hues/
```

**Linting and Type Checking:**
```bash
check   # runs ruff linter and pyright on hues/, tests/, migrations/
```

**Running Tests:**
```bash
pytest                    # run all tests
pytest tests/path/test.py # run specific test file
pytest -k "test_name"     # run tests matching pattern
```

**Services:**
```bash
up  # bring up services stack via process-compose
```

**Dependency Management:**
```bash
poetry add <package>      # add a dependency
poetry install            # install dependencies
```

## Code Quality Standards

- Line length: 120 characters
- Linter: ruff with E, F, B, T rule sets enabled
- Type checker: pyright in strict mode
- Formatter: ruff format + isort
- Particular modules must be imported as, and have their members accessed through, abbreviated local aliases:
  - typing: `import typing as t ... foo: t.Annotated[list, "whatever"]`
  - pydantic: `import pydantic as p`
  - re: `import re as regex ... regex.search(...)`
- SCREAMING_CASE is not permitted; use PascalCase for all constants
- Apart from aliased modules, variable names must be at least two characters long
