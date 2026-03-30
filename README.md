# sast-cli — Advanced Static Analysis Engine for C/C++

sast-cli is a high-performance static analysis (SAST) engine written in Rust for detecting and validating memory corruption and input-driven vulnerabilities in C/C++ codebases.

It combines interprocedural dataflow analysis with multi-stage validation (CFG, feasible path, dominance, and state tracking) to significantly reduce false positives while maintaining high detection coverage.

---

## Overview

Traditional SAST tools often suffer from either:

* High recall but noisy results (false positives), or
* High precision but limited detection

sast-cli bridges this gap using a **two-stage pipeline**:

### Detection Phase

* Taint analysis (source → sink)
* Interprocedural dataflow tracking
* Pointer and alias propagation
* Function call resolution

### Validation Phase

* Control Flow Graph (CFG)
* Feasible path analysis (constraint-aware)
* Dominator analysis (execution guarantees)
* Memory state tracking (alloc → free → use)
* Structural validation for unsafe APIs

This ensures reported vulnerabilities are not just possible, but **actually exploitable**.

---

## Features

### Detection Capabilities

* Interprocedural taint tracking
* Pointer & alias tracking
* Function pointer resolution
* AST-based analysis (tree-sitter)

### Validation Engine

* Taint-based validation (source → sink path)
* Structural validation (unsafe APIs like strcpy/sprintf)
* State-based validation (UAF / double free)
* Feasible path analysis (constraint-aware CFG traversal)
* Dominance analysis (guaranteed execution ordering)

### Vulnerability Coverage

* Buffer Overflow (including pointer arithmetic)
* Use-After-Free (UAF)
* Double Free
* Format String
* Command Injection

---

## Quick Start (2 Minutes)

### Clone and Build

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

### Run Your First Scan

```bash
sast-cli --table ./your_project
```

---

## Installation Options

### Option 1: Build from Source (Recommended)

```bash
git clone https://github.com/Tanish-26/sast-cli.git
cd sast-cli/rust
cargo build --release
```

---

### Option 2: Install Globally

```bash
cargo install --path apps/sast-cli
```

---

### Option 3: Run Without Installing

```bash
cargo run -p sast-cli -- ./test.c --json
```

---

## CLI Usage

```bash
sast-cli [OPTIONS] <PATHS>...
```

### Arguments

| Argument  | Description                  |
| --------- | ---------------------------- |
| `<PATHS>` | Files or directories to scan |

---

## CLI Options

### Output Formats

| Option      | Description                     |
| ----------- | ------------------------------- |
| `--table`   | Human-readable output (default) |
| `--json`    | Machine-readable JSON           |
| `--report`  | Markdown report                 |
| `--summary` | Compact summary                 |
| `--sarif`   | SARIF output (GitHub Security)  |

---

### Filtering & Validation

| Option             | Description                   |
| ------------------ | ----------------------------- |
| `--validated-only` | Show only validated findings  |
| `--min-confidence` | low | medium | high           |
| `--show-path`      | Show validated execution path |
| `--show-notes`     | Show validation reasoning     |

---

### Prioritization

| Option                     | Description                     |
| -------------------------- | ------------------------------- |
| `--sort-by-exploitability` | Sort findings by exploitability |
| `--top <N>`                | Show top N results              |

---

### Other

| Option              | Description                           |
| ------------------- | ------------------------------------- |
| `--baseline <FILE>` | Compare against baseline              |
| `--language <LANG>` | Force language (c | cpp | javascript) |
| `--debug-validator` | Enable validator debug logs           |

---

## Common Usage

### Scan Directory

```bash
sast-cli ./project
```

---

### Scan Single File

```bash
sast-cli main.c
```

---

### JSON Output

```bash
sast-cli --json ./project > results.json
```

---

### Markdown Report

```bash
sast-cli --report ./project > report.md
```

---

## Advanced Usage

### High Confidence Findings Only

```bash
sast-cli --min-confidence high ./project
```

---

### Only Validated Vulnerabilities

```bash
sast-cli --validated-only ./project
```

---

### Show Execution Path

```bash
sast-cli --show-path ./project
```

Example:

```
free@file.c:20 → use@file.c:25
```

---

### Show Validation Notes

```bash
sast-cli --show-notes ./project
```

Example notes:

* dominance_confirmed
* feasible_path_confirmed
* structural_overflow_no_bounds_check

---

### Prioritize by Exploitability

```bash
sast-cli --sort-by-exploitability --top 10 ./project
```

---

### Best Practice Scan

```bash
sast-cli --validated-only --min-confidence high --sort-by-exploitability ./project
```

---

## Docker Usage

### Pull Image

```bash
docker pull tanishs26/sast-cli:latest
```

---

### Scan Current Directory

```bash
docker run --rm -v $(pwd):/scan tanishs26/sast-cli:latest --table /scan
```

---

### Scan External Project

```bash
docker run --rm \
-v /absolute/path/to/project:/scan \
tanishs26/sast-cli:latest \
--table /scan
```

---

### Important Note

Inside Docker, always scan `/scan`, not your local path.

---

## SARIF Integration (CI/CD)

```bash
sast-cli --sarif ./project > results.sarif
```

Upload to the GitHub Security tab.

---

## Example Output

Command
```bash
sast-cli --min-confidence high --show-path  ../../Scanner-test/
```

```bash
Filtered results: confidence filter applied

RBOM: score=89 grade=C findings=4 exploitability=MEDIUM tainted=true
Summary: critical=0 high=4 medium=0 low=0 validated=4 high_confidence=4
Top risks:
  #1   HIGH      MEDIUM c.use_after_free           ../../Scanner-test/testcase.c:22 (1×)
  #2   HIGH      MEDIUM c.buffer_overflow          ../../Scanner-test/testcase.c:14 (1×)
  #3   HIGH      MEDIUM c.double_free              ../../Scanner-test/testcase.c:28 (1×)
  #4   HIGH      MEDIUM c.double_free              ../../Scanner-test/testcase2.c:38 (1×)

#     OCC   LINE    COL     SEV        CONF    EXPLOIT    RULE                                DESC                          FILE
1     1     22      13      HIGH  HIGH    HIGH  c.use_after_free                    Use after free                ../../Scanner-test/testcase.c
2     1     14      9       HIGH  HIGH    HIGH  c.buffer_overflow                   Unsafe copy/format            ../../Scanner-test/testcase.c
3     1     28      5       HIGH  HIGH    MEDIUM  c.double_free                       Double free                   ../../Scanner-test/testcase.c
4     1     38      5       HIGH  HIGH    MEDIUM  c.double_free                       Double free                   ../../Scanner-test/testcase2.c

#1 c.use_after_free (1 occurrences)
  Why this matters: Using freed memory is undefined behavior and can lead to crashes, memory corruption, and exploitation.
  Suggested fix: Do not use a pointer after `free()`. Clear it (`p = NULL`) and ensure ownership/lifetimes prevent reuse.
  Primary: ../../Scanner-test/testcase.c:22:13
  Exploitability: HIGH (90)
  Path: free@../../Scanner-test/testcase.c:21:5 -> use@../../Scanner-test/testcase.c:22:5

#2 c.buffer_overflow (1 occurrences)
  Why this matters: Buffer overflows can corrupt memory, causing crashes and potentially enabling code execution or privilege escalation.
  Suggested fix: Apply input validation and safer APIs for this pattern.
  Primary: ../../Scanner-test/testcase.c:14:9
  Exploitability: HIGH (80)
  Path: memset@../../Scanner-test/testcase.c:14:9

#3 c.double_free (1 occurrences)
  Why this matters: Freeing the same pointer twice is undefined behavior and can corrupt allocator state, sometimes enabling exploitation.
  Suggested fix: Ensure each allocation is freed exactly once. Clear pointers after free (`p = NULL`) and avoid duplicated ownership.
  Primary: ../../Scanner-test/testcase.c:28:5
  Exploitability: MEDIUM (70)
  Path: free@../../Scanner-test/testcase.c:27:5 -> free@../../Scanner-test/testcase.c:28:5

#4 c.double_free (1 occurrences)
  Why this matters: Freeing the same pointer twice is undefined behavior and can corrupt allocator state, sometimes enabling exploitation.
  Suggested fix: Ensure each allocation is freed exactly once. Clear pointers after free (`p = NULL`) and avoid duplicated ownership.
  Primary: ../../Scanner-test/testcase2.c:38:5
  Exploitability: MEDIUM (70)
  Path: free@../../Scanner-test/testcase2.c:36:5 -> free@../../Scanner-test/testcase2.c:38:5

```

---

## Output Meaning

| Field   | Description                      |
| ------- | -------------------------------- |
| SEV     | Severity (impact)                |
| CONF    | Confidence (validation strength) |
| EXPLOIT | Exploitability likelihood        |

---

## Architecture

```
sast-c          C/C++ analysis engine
sast-js         JavaScript engine (experimental)
sast-validator  multi-stage validation engine
rbom            risk scoring
sast-cli        CLI interface
sast-api        REST API (in progress)
```

---

## Version v1.2.0 Highlights

* Dominance-aware validation (CFG dominators)
* Feasible-path validation (constraint-based)
* Multi-mode validation:

  * Taint
  * Structural
  * State-based
  * Path-based
  * Dominance
* SARIF output support
* Improved confidence scoring
* Reduced false positives

---

## Use Cases

* Bug bounty research
* Kernel/driver auditing
* CI/CD security scanning
* Secure code review
* Large-scale codebase analysis

---

## Known Limitations

* Advanced SMT solving (planned)
* Deep points-to analysis (planned)
* Full symbolic execution (future work)

---

## Roadmap

* SARIF GitHub native integration
* AI-based vulnerability explanation
* CI/CD automation
* Web dashboard

---

## Author

Tanish (tanishs26)
Security Researcher | Bug Bounty Hunter

---

## Support

If you find this project useful:

* Star the repository
* Use the Docker image
* Contribute improvements

---

