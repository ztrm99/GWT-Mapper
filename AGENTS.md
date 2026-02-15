# Repository Guidelines

## Project Structure & Module Organization
- Core extension code is in `src/main/java`.
- Unit tests are in `src/test/java` (JUnit 5).
- Gradle wrapper and build config live at `gradlew`, `build.gradle.kts`, and `settings.gradle.kts`.
- Reference tooling/scripts are in `reference/`.
- `extension-template-project/` is a separate template project; do not mix production changes into it unless intentionally updating the template.
- Build artifacts are generated under `build/` (for example `build/libs/gwt-rpc-mapper.jar`) and should not be edited manually.

## Build, Test, and Development Commands
- `./gradlew clean` removes generated outputs.
- `./gradlew build` compiles, runs tests, and produces the extension JAR.
- `./gradlew test` runs unit tests only.
- `./gradlew test --tests GwtDetectorTest` runs a single test class while iterating.

Use `gradlew.bat` instead of `./gradlew` on Windows.

## Coding Style & Naming Conventions
- Language level is Java 17; keep code compatible with the toolchain in `build.gradle.kts`.
- Use 4-space indentation and UTF-8 encoding.
- Class names: `PascalCase` (for example `GwtDownloader`); methods/fields: `camelCase`; constants: `UPPER_SNAKE_CASE`.
- Keep methods focused and side effects explicit, especially in Burp handler callbacks.
- Prefer small, testable utility methods for parsing/detection logic.

## Testing Guidelines
- Framework: JUnit Jupiter (`org.junit.jupiter`).
- Name test classes `*Test.java` and test methods with behavior-focused names (for example `parseResponseParsesOkPayload`).
- Add/adjust tests for parser and detector changes before merging.
- Run `./gradlew test` before opening a PR.

## Commit & Pull Request Guidelines
- No Git history is available in this workspace snapshot, so no enforced historical convention can be inferred.
- Recommended commit format: imperative, scoped subject (for example `parser: handle empty RPC payload`).
- Keep commits focused; avoid mixing refactors with behavior changes.
- PRs should include:
  - What changed and why.
  - Validation steps/commands run.
  - Screenshots or short notes for UI changes in the Burp tab.
  - Linked issue/ticket when applicable.

## Security & Configuration Tips
- Do not commit captured traffic, session tokens, or local Burp artifacts.
- Use test-safe sample payloads in fixtures and docs.
