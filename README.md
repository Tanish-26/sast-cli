# SAST-CLI — Static Analysis for C/C++

A high-performance **Rust-based SAST engine** for detecting memory corruption vulnerabilities in C/C++ codebases.

---

## Features

* Taint Analysis (source → sink)
* Interprocedural Dataflow
* Pointer & alias tracking
* Vulnerability Detection:

  * Buffer Overflow (incl. pointer arithmetic)
  * Use-After-Free
  * Format String
  * Command Injection

---

## Installation (Local / Git)

### Option 1 — Install via Cargo (Recommended)

```bash
git clone https://github.com/Tanish-26/sast-cli.git
cd sast-cli/rust
cargo build --release
```

Binary will be available at:

```bash
target/release/sast-cli
```

(Optional) Add to PATH:

```bash
export PATH=$PATH:$(pwd)/target/release
```

---

### Option 2 — Install globally

```bash
cargo install --path apps/sast-cli
```

Then run:

```bash
sast-cli --help
```

---

### Option 3 — Run without installing

```bash
cargo run -p sast-cli -- ./test.c --json
```

---

## Output Formats

```bash
--table     # human readable
--json      # machine readable
--report    # markdown report
```

## Real Scan Example

```bash
docker run --rm -v /path/to/xrt:/scan tanishs26/sast-cli:latest --table /scan
```

Output:

```
RBOM: score=89 grade=C findings=41 exploitability=MEDIUM

HIGH    c.buffer_overflow.pointer_arithmetic
HIGH    c.use_after_free
MEDIUM  c.format_string
```

---

## Docker Usage

```bash
docker run --rm -v $(pwd):/app tanishs26/sast-cli:latest --table /app
```

---

## Example Vulnerability

```
Path: buf -> buf+sz -> sprintf
Type: Pointer arithmetic buffer overflow
```

---

## Local Development

```bash
cargo run -p sast-cli -- ./test.c --json
```

---

## Architecture

* `sast-c` → C/C++ analysis engine
* `sast-js` → JS analysis (experimental)
* `rbom` → risk scoring
* `sast-cli` → CLI interface
* `sast-api` → REST API

---

## Roadmap

* SARIF output (GitHub Security)
* AI vulnerability explanation
* CI/CD integration
* Web dashboard

---

## Author

Tanish (tanishs26)

---

## ⭐ If useful, give a star!
