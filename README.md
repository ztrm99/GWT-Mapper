# GWT RPC Mapper (Burp Extension)

Burp Suite extension (Montoya API) for controlled GWT RPC penetration testing.

## Features

- Detects GWT artifacts and traffic patterns:
  - `*.cache.js`
  - `*.nocache.js`
  - `*.gwt.rpc`
  - GWT-RPC request signatures/headers
- Raises informational scanner issues where detections occur.
- Adds a `GWT Scanner` suite tab with:
  - Internal subviews similar to scanner dashboards:
  - `Dashboard` view (artifacts + previews + analysis controls)
  - `Scanner` view (persistent compiled methods inventory)
  - Artifact table
  - Configurable passive max body size threshold
  - Native Burp-style request/response viewers for selected artifacts
  - `TOO BIG FILE` placeholder for large request/response previews
  - `Analyze Selected Item(s)` for one or multiple selected rows
  - `Analyze HTTP History` action to process full Proxy history and enrich mappings
  - Analysis subtabs: `Summary`, `Methods`, `Headers`
  - `Methods` as sortable/exportable table
  - `Runs` tab to keep history of analysis executions
  - History scan controls: progress label + cancel button
  - Optional scope-only history analysis
  - Automatic `.nocache.js` expansion to discovered `.cache.js` permutations (gwtmap-style heuristic)
  - Folder configuration (persistent)
  - Toggle to enable/disable passive scan
  - Download selected/all artifacts
  - Temporary folder option
  - Filter, clear, and CSV export
- Adds `GWT` request/response editor tabs to parse RPC payloads into a readable table.

## Build

```bash
./gradlew build
```

JAR output:

- `build/libs/gwt-rpc-mapper.jar`

## Load in Burp

1. Build the jar.
2. In Burp: `Extensions` -> `Installed` -> `Add` -> select the jar from `build/libs/`.

## Notes

- Artifact downloads reuse authentication/session headers from the request that discovered the artifact (when available).
- RPC parsing currently provides structured tokenization for analyst readability; it is not a complete semantic GWT serializer/deserializer.
