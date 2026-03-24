# Rust SAST Engine (starter)

This folder is a Cargo workspace containing:

- `crates/sast-js`: JS tree-sitter scanning + minimal intra-procedural taint to `eval(...)`
- `crates/sast-c`: C/C++ tree-sitter scanning + starter taint + memory rules
- `crates/rbom`: RBOM scoring for findings
- `apps/sast-cli`: CLI wrapper
- `services/sast-api`: HTTP API for scanning (Axum)
- `services/rbom-api`: HTTP API for RBOM scoring (Axum)

## Local run

```bash
cd rust
cargo run -p sast-api
```

## CLI scan examples

```bash
cd rust
cargo run -p sast-cli -- ../path/to/file.c --json
cargo run -p sast-cli -- ../path/to/dir
```

## Example request

```bash
curl -sS localhost:8080/scan \\
  -H 'content-type: application/json' \\
  -d '{"code":"const x = document.getElementById(\"id\").value; eval(x)","path":"demo.js"}' | jq
```
