# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Canonical Guidance

Follow `AGENTS.md` for repository guidelines (build/test commands, architecture, Burp/Swing threading rules, testing contract, and security/redaction).

## Claude-Specific Notes

- Keep changes small and test-backed. Prefer adding/adjusting JUnit tests when changing detection/parsing/extraction logic.
- This project currently uses the Java default package (no sub-packages). Do not introduce new packages unless intentionally migrating the whole codebase.
