# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

A filtering mDNS repeater written in Rust. The project uses Nix flakes for reproducible development environments.

## Development Environment

The project uses direnv with Nix flakes. Enter the development shell automatically via direnv or manually with `nix develop`.

## Common Commands

**Formatting:**
```bash
format  # runs cargo fmt
```

**Linting:**
```bash
check   # runs cargo check and clippy
```

**Running Tests:**
```bash
test                     # run all tests via cargo test
cargo test test_name     # run tests matching pattern
```

**Development:**
```bash
watch   # watch and rebuild on changes
```

## Code Quality Standards

- Linter: clippy with warnings as errors
- Formatter: rustfmt
- DNS record types use SCREAMING_CASE (A, PTR, TXT, etc.) for consistency with DNS spec
