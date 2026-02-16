# Repository Guidelines (Canonical)

This is the source-of-truth repository guidance for humans and coding agents. Keep `CLAUDE.md` brief and point back here.

## Project Overview

GWT-RPC Mapper is a Burp Suite extension (Montoya API) for detecting and analyzing Google Web Toolkit (GWT) RPC traffic. It detects GWT artifacts (`.cache.js`, `.nocache.js`, `.gwt.rpc`), parses pipe-delimited RPC payloads, extracts likely service/method names, and exposes a Swing UI in Burp.

## Project Structure

- Core extension code: `src/main/java`
- Unit tests (JUnit 5): `src/test/java`
- Build config: `build.gradle.kts`, `settings.gradle.kts`, `gradlew`, `gradlew.bat`
- Reference scripts/prototypes: `reference/`
- Build artifacts: `build/` (for example `build/libs/gwt-rpc-mapper.jar`) should not be edited manually

Note: Source currently uses the Java default package (no `package ...;` declarations). Keep it consistent unless intentionally migrating to packages.

## Build, Test, Run

Windows (PowerShell):
- `.\gradlew.bat clean`
- `.\gradlew.bat build`
- `.\gradlew.bat test`
- `.\gradlew.bat test --tests GwtDetectorTest`

macOS/Linux:
- `./gradlew clean`
- `./gradlew build`
- `./gradlew test`
- `./gradlew test --tests GwtDetectorTest`

JAR output:
- `build/libs/gwt-rpc-mapper.jar`

## Load In Burp

1. Build the jar (`build/libs/gwt-rpc-mapper.jar`).
2. In Burp: `Extensions` -> `Installed` -> `Add` -> select the jar.
3. If Burp asks for a Java version/runtime: this project targets Java 17 (see `build.gradle.kts`).

## Architecture (Current Files)

All production sources are in `src/main/java` (default package).

| File | Role |
|------|------|
| `Extension.java` | Main entry point. Owns UI wiring, Burp callbacks, passive scan integration, analysis orchestration, and export. |
| `GwtDetector.java` | Stateless detection utilities (artifact URL patterns, RPC request signatures/headers, artifact path extraction). |
| `GwtRpcParser.java` | Pipe-delimited GWT-RPC tokenization and table-like parsing (request/response) for analyst readability. |
| `MethodExtractor.java` | Heuristics for extracting likely interfaces/method names from compiled artifacts (gwtmap-style strategies). |
| `ArtifactStore.java` | Thread-safe in-memory store for discovered artifacts and associated HTTP context. |
| `GwtArtifact.java` | Artifact model/record (host/path/type/resolution + source context + timestamp). |
| `GwtDownloader.java` | Artifact downloading, reusing auth/session headers from the source request when available. |

## Burp + Swing Rules (Non-Negotiable)

- Do not block Burp threads. Anything non-trivial (downloads, parsing, history analysis) must run off-thread.
- UI updates must be performed on the Swing EDT (use `SwingUtilities.invokeLater` / `invokeAndWait` as appropriate).
- Keep handler callbacks (passive scan, HTTP handlers, editor providers) small and explicit about side effects.
- Prefer small, testable pure helpers for detection/parsing/extraction logic.

## Coding Style

- Java 17, 4-space indentation, UTF-8 (match `build.gradle.kts`).
- Names: `PascalCase` classes, `camelCase` methods/fields, `UPPER_SNAKE_CASE` constants.
- Keep methods focused; avoid hidden global state in Burp callbacks.

## Testing Contract

- Framework: JUnit Jupiter (`org.junit.jupiter`).
- Tests live in `src/test/java` and are named `*Test.java`.
- If you change:
  - detector regexes/signatures: add tests in `GwtDetectorTest`
  - RPC parsing logic: add tests in `GwtRpcParserTest`
  - method extraction heuristics: add tests in `MethodExtractorTest`
- Prefer synthetic fixtures. Do not add real customer traffic or live tokens to tests.

## Commits & PRs

- Recommended commit subject: imperative, scoped (example: `parser: handle empty RPC payload`).
- Keep commits focused; avoid mixing refactors with behavior changes.
- PRs should include:
  - what changed and why
  - validation commands run (for example `.\gradlew.bat test`)
  - screenshots/notes for Burp UI changes

## Security & Redaction

- Do not commit captured traffic, session tokens, cookies, auth headers, or local Burp state.
- Keep fixtures and docs test-safe: synthetic hosts, synthetic payloads, redacted headers.
- Assume anything under version control will be shared publicly at some point.
