# SAST-CLI — Static Analysis for C/C++

A high-performance **Rust-based SAST engine** for detecting memory corruption vulnerabilities in C/C++ codebases.

---

## Features

- **Taint Analysis** (source → sink)
- **Inter-procedural Dataflow Tracking**
- **Pointer & Alias Tracking (basic)**
- **Fast AST-based scanning (tree-sitter)**

### Vulnerability Detection

- Buffer Overflow (including pointer arithmetic)
- Use-After-Free (UAF)
- Double Free
- Format String
- Command Injection

---

## Installation

### Option 1: Build from Source (Recommended)

```bash
git clone https://github.com/Tanish-26/sast-cli.git
cd sast-cli/rust
cargo build --release
````

Binary location:

```bash
target/release/sast-cli
```

(Optional) Add to PATH:

```bash
export PATH=$PATH:$(pwd)/target/release
```

---

### Option 2: Install Globally

```bash
cargo install --path apps/sast-cli
```

Run:

```bash
sast-cli --help
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

| Argument     | Description                                       |
| ------------ | ------------------------------------------------- |
| `<PATHS>...` | Files or directories to scan (C, C++, JavaScript) |

---

## CLI Options

| Option              | Description                               |
| ------------------- | ----------------------------------------- |
| `--json`            | Output results in JSON format             |
| `--summary`         | Show compact summary                      |
| `--table`           | Human-readable table output (default)     |
| `--report`          | Generate Markdown report                  |
| `--baseline <FILE>` | Compare against baseline JSON             |
| `--language <LANG>` | Force language (`c`, `cpp`, `javascript`) |
| `-h, --help`        | Show help menu                            |

---

## Examples

### Scan a Directory

```bash
sast-cli --table ./project
```

---

### Scan Single File

```bash
sast-cli --json main.c
```

---

### Generate Markdown Report

```bash
sast-cli --report ./project > report.md
```

---

### Baseline Comparison

```bash
sast-cli --baseline baseline.json ./project
```

---

## Output Formats

| Format     | Description             |
| ---------- | ----------------------- |
| `--table`  | Human-readable output   |
| `--json`   | Machine-readable output |
| `--report` | Markdown report         |

---

## Sample Output

### Table Output

```text
RBOM: score=89 grade=C findings=16 exploitability=MEDIUM tainted=true

LINE    COL     SEV     RULE
14      9       HIGH    c.buffer_overflow
22      13      HIGH    c.use_after_free
28      5       HIGH    c.double_free
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
docker run --rm -v $(pwd):/data tanishs26/sast-cli:latest --table .
```

---

### Scan Specific Project

```bash
docker run --rm \
-v /path/to/project:/data \
tanishs26/sast-cli:latest \
--table /data
```

---

### Real Scan Example

```bash
docker run --rm -v /path/to/xrt:/scan tanishs26/sast-cli:latest --table /scan
```

Output:

```text
RBOM: score=89 grade=C findings=16 exploitability=MEDIUM tainted=true
Summary: critical=0 high=4 medium=12 low=0
Top risks:
  #1   HIGH      MEDIUM c.buffer_overflow          /data/testcase.c:14 (1×)
  #2   HIGH      MEDIUM c.use_after_free           /data/testcase.c:22 (1×)
  #3   HIGH      MEDIUM c.double_free              /data/testcase.c:28 (1×)
  #4   HIGH      MEDIUM c.double_free              /data/testcase2.c:38 (1×)
  #5   MEDIUM    MEDIUM c.buffer_overflow          /data/testcase.c:7 (1×)

#     OCC   LINE    COL     SEV        EXPLOIT    RULE                                DESC                          FILE
1     1     14      9       HIGH       MEDIUM     c.buffer_overflow                   Unsafe copy/format            /data/testcase.c
2     1     22      13      HIGH       MEDIUM     c.use_after_free                    Use after free                /data/testcase.c
3     1     28      5       HIGH       MEDIUM     c.double_free                       Double free                   /data/testcase.c
4     1     38      5       HIGH       MEDIUM     c.double_free                       Double free                   /data/testcase2.c
5     1     7       5       MEDIUM     MEDIUM     c.buffer_overflow                   Unsafe copy/format            /data/testcase.c
6     1     63      5       MEDIUM     MEDIUM     c.format_string                     Untrusted format string       /data/testcase.c
7     1     29      5       MEDIUM     MEDIUM     c.buffer_overflow                   Unsafe copy/format            /data/testcase2.c
8     1     43      5       MEDIUM     MEDIUM     c.format_string                     Untrusted format string       /data/testcase2.c
9     1     28      5       MEDIUM     MEDIUM     c.format_string                     Untrusted format string       /data/testcase_extreme.c
10    1     23      9       MEDIUM     MEDIUM     c.format_string                     Untrusted format string       /data/testcase_ghost.c
11    1     16      9       MEDIUM     MEDIUM     c.format_string                     Untrusted format string       /data/testcase_ghost_in_machine.c
12    1     25      5       MEDIUM     MEDIUM     c.format_string                     Untrusted format string       /data/testcase_god_mode.c
13    1     9       9       MEDIUM     MEDIUM     c.format_string                     Untrusted format string       /data/testcase_in_memory.c
14    1     22      9       MEDIUM     MEDIUM     c.format_string                     Untrusted format string       /data/testcase_in_memory.c
15    1     25      9       MEDIUM     MEDIUM     c.format_string                     Untrusted format string       /data/testcase_nuclear.c
16    1     21      9       MEDIUM     MEDIUM     c.format_string                     Untrusted format string       /data/testcase_wash_taint.c
```

---

## Example Vulnerability

```
Path: buf → buf+sz → sprintf
Type: Pointer arithmetic buffer overflow
```

---

## Architecture

| Component  | Description                        |
| ---------- | ---------------------------------- |
| `sast-c`   | C/C++ analysis engine              |
| `sast-js`  | JavaScript analysis (experimental) |
| `rbom`     | Risk scoring engine                |
| `sast-cli` | CLI interface                      |
| `sast-api` | REST API service                   |

---

## Known Limitations

* Function pointer resolution (planned)
* Advanced alias (points-to) analysis (planned)
* SMT-based constraint solving (planned)

---

## Roadmap

* [ ] Function pointer resolution
* [ ] SARIF output (GitHub Security tab)
* [ ] AI-based vulnerability explanation
* [ ] CI/CD pipeline integration
* [ ] Web dashboard

---

## Local Development

```bash
cargo run -p sast-cli -- ./test.c --json
```

---

## Author

**Tanish (tanishs26)**
Security Researcher | Bug Bounty Hunter

---

## ⭐ Support

If you find this project useful:

* ⭐ Star the repository
* Use the Docker image
* Contribute improvements

---



