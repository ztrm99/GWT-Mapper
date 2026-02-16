# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

GWT-RPC Mapper is a Burp Suite extension (Montoya API) for detecting and analyzing Google Web Toolkit (GWT) RPC traffic during penetration tests. It identifies GWT artifacts (`.cache.js`, `.nocache.js`, `.gwt.rpc`), parses pipe-delimited RPC payloads, extracts service methods, and provides a UI with Dashboard and Scanner tabs inside Burp.

## Build & Test Commands

```bash
./gradlew build          # compile, test, and produce build/libs/gwt-rpc-mapper.jar
./gradlew test           # run unit tests only
./gradlew test --tests GwtDetectorTest   # run a single test class
./gradlew clean          # remove generated outputs
```

On Windows use `gradlew.bat` instead of `./gradlew`.

## Architecture

All source is in the default package under `src/main/java/`. No sub-packages.

| File | Role |
|------|------|
| `Extension.java` | Main entry point. Implements Montoya interfaces (`BurpExtension`, `PassiveScanCheck`, `HttpHandler`, editor providers, context menu provider). Builds the Swing UI, orchestrates scanning, artifact analysis, method extraction, and CSV export. ~1700 lines. |
| `GwtDetector.java` | Stateless utility. Regex-based detection of GWT artifact URLs and RPC request signatures (body pattern `\d+\|\d+\|.*`, `X-GWT-*` headers). Extracts and resolves artifact paths from HTML/JS content. |
| `GwtRpcParser.java` | Parses pipe-delimited GWT-RPC payloads (requests and responses) into structured token tables with string-table resolution and field-name inference. |
| `ArtifactStore.java` | Thread-safe in-memory store keyed by `host|path|type`. Merges artifacts preferring entries with richer HTTP context. |
| `GwtArtifact.java` | Immutable record (host, path, type, resolved URL, source request/response, timestamp). |
| `GwtDownloader.java` | Downloads artifacts via HTTP, reusing auth headers (Cookie, Authorization, X-CSRF-Token) from the source request. |

### Key design patterns

- **Single compile-only dependency**: Burp Montoya API 2025.10. No runtime dependencies beyond the JDK.
- **Dedicated executor**: Passive scan handlers run on a single-thread executor to avoid blocking Burp's proxy threads.
- **`.nocache.js` expansion**: Heuristic borrowed from gwtmap (see `reference/`) — downloads a `.nocache.js` file and extracts cache permutation hashes to discover `.cache.js` files automatically.
- **Method extraction heuristics**: Multiple regex strategies in `extractCacheMethodsLikeGwtMap()` parse compiled `.cache.js` to recover service interface/method names.

## Coding Conventions

- Java 17, 4-space indentation, UTF-8.
- `PascalCase` classes, `camelCase` methods/fields, `UPPER_SNAKE_CASE` constants.
- Test classes named `*Test.java` with behavior-focused method names (e.g., `parseResponseParsesOkPayload`).
- Commit format: imperative, scoped subject (e.g., `parser: handle empty RPC payload`).

## Reference Scripts

`reference/gwtmap.py` and `gwtmap_ng.py` are Python prototypes (F-Secure Labs lineage) that inspired the Java method-extraction logic. Useful for understanding the heuristics but not part of the build.
