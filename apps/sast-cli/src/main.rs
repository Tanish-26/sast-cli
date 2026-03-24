use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use sast_core::{poc, Language};
use serde_json::Value;

#[derive(Debug, Parser)]
#[command(name = "sast-cli")]
struct Args {
    /// Files/directories to scan (JavaScript, C, C++)
    #[arg(required = true)]
    paths: Vec<PathBuf>,

    /// Emit JSON instead of human-readable output
    #[arg(long)]
    json: bool,

    /// Emit a compact summary
    #[arg(long, conflicts_with_all = ["json", "table"])]
    summary: bool,

    /// Emit a human-readable table (default when not using --json/--summary)
    #[arg(long, conflicts_with_all = ["json", "summary"])]
    table: bool,

    /// Emit a Markdown report
    #[arg(long, conflicts_with_all = ["json", "summary", "table"])]
    report: bool,

    /// Compare against a baseline JSON file (also updates baseline to current scan)
    #[arg(long)]
    baseline: Option<PathBuf>,

    /// Force language for single-file scans: javascript|c|cpp
    #[arg(long)]
    language: Option<String>,
}

fn main() -> ExitCode {
    let args = Args::parse();

    let mut findings = Vec::new();
    let mut files = Vec::new();

    for p in &args.paths {
        if p.is_dir() {
            for entry in walkdir::WalkDir::new(p) {
                let entry = match entry {
                    Ok(e) => e,
                    Err(e) => {
                        eprintln!("{e}");
                        return ExitCode::from(2);
                    }
                };
                if entry.file_type().is_file() {
                    let path = entry.path();
                    if let Some(ext) = path.extension().and_then(|s| s.to_str()) {
                        let ext = ext.to_ascii_lowercase();
                        if matches!(
                            ext.as_str(),
                            "js" | "mjs" | "cjs" | "c" | "h" | "cc" | "cpp" | "cxx" | "hh" | "hpp" | "hxx"
                        ) {
                            files.push(path.to_path_buf());
                        }
                    }
                }
            }
        } else {
            files.push(p.to_path_buf());
        }
    }

    for f in &files {
        let src = match fs::read_to_string(f) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("{}: {e}", f.display());
                return ExitCode::from(2);
            }
        };
        let path = f.to_string_lossy().to_string();
        let lang = match infer_language(f, args.language.as_deref()) {
            Some(l) => l,
            None => {
                eprintln!(
                    "unsupported file extension for {} (use --language javascript|c|cpp)",
                    f.display()
                );
                return ExitCode::from(2);
            }
        };
        let mut file_findings = match lang {
            Language::JavaScript => match sast_js::scan_eval_taint(&src, &path) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("{e}");
                    return ExitCode::from(2);
                }
            },
            Language::C | Language::Cpp => match sast_c::scan(&src, &path, lang) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("{e}");
                    return ExitCode::from(2);
                }
            },
        };
        findings.append(&mut file_findings);
    }

    poc::attach(&mut findings);
    sort_and_rank(&mut findings);

    let rbom = rbom::score(&findings);

    if let Some(baseline_path) = &args.baseline {
        let old = load_baseline_findings(baseline_path).unwrap_or_else(|e| {
            eprintln!("{e}");
            std::process::exit(2);
        });
        let diff = compare_findings(&old, &findings);
        let new_count = diff.new.len();
        let fixed_count = diff.fixed.len();
        let unchanged_count = diff.unchanged.len();
        // Always emit JSON in baseline mode.
        let out = serde_json::json!({
            "new": diff.new,
            "fixed": diff.fixed,
            "unchanged": diff.unchanged,
            "summary": {
                "new": new_count,
                "fixed": fixed_count,
                "unchanged": unchanged_count,
            }
        });
        println!("{}", serde_json::to_string_pretty(&out).unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}")));
        // Save/refresh baseline for next run.
        if let Err(e) = save_baseline(baseline_path, &findings, &rbom) {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
        eprintln!("New: {}  Fixed: {}", new_count, fixed_count);
        return if new_count == 0 {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(1)
        };
    }

    if args.json {
        let out = serde_json::json!({
            "findings": findings,
            "rbom": rbom,
        });
        match serde_json::to_string_pretty(&out) {
            Ok(s) => println!("{s}"),
            Err(e) => {
                eprintln!("{e}");
                return ExitCode::from(2);
            }
        }
    } else if args.report {
        print_report(&rbom, &findings);
    } else if args.summary {
        print_summary(&rbom, &findings);
    } else {
        // Default: table output (or explicit --table).
        print_table(&rbom, &findings);
    }

    if findings.is_empty() { ExitCode::SUCCESS } else { ExitCode::from(1) }
}

fn infer_language(path: &PathBuf, forced: Option<&str>) -> Option<Language> {
    if let Some(forced) = forced {
        return match forced.to_ascii_lowercase().as_str() {
            "javascript" | "js" => Some(Language::JavaScript),
            "c" => Some(Language::C),
            "cpp" | "cxx" | "c++" => Some(Language::Cpp),
            _ => None,
        };
    }

    let ext = path.extension()?.to_str()?.to_ascii_lowercase();
    match ext.as_str() {
        "js" | "mjs" | "cjs" => Some(Language::JavaScript),
        "c" | "h" => Some(Language::C),
        "cc" | "cpp" | "cxx" | "hpp" | "hh" | "hxx" => Some(Language::Cpp),
        _ => None,
    }
}

fn print_summary(rbom: &rbom::RbomScore, findings: &[sast_core::Finding]) {
    let mut low = 0usize;
    let mut medium = 0usize;
    let mut high = 0usize;
    let mut critical = 0usize;
    for f in findings {
        match f.severity {
            sast_core::Severity::Low => low += 1,
            sast_core::Severity::Medium => medium += 1,
            sast_core::Severity::High => high += 1,
            sast_core::Severity::Critical => critical += 1,
        }
    }

    let exploit = format!("{:?}", rbom.exploitability).to_ascii_uppercase();
    println!(
        "RBOM: score={} grade={} findings={} exploitability={} tainted={}",
        rbom.score, rbom.grade, rbom.findings, exploit, rbom.tainted
    );
    println!(
        "Findings: critical={} high={} medium={} low={}",
        critical, high, medium, low
    );
}

fn print_table(rbom: &rbom::RbomScore, findings: &[sast_core::Finding]) {
    use std::io::IsTerminal;

    let use_color = std::io::stdout().is_terminal() && std::env::var("NO_COLOR").is_err();

    let exploit = format!("{:?}", rbom.exploitability).to_ascii_uppercase();
    println!(
        "RBOM: score={} grade={} findings={} exploitability={} tainted={}",
        rbom.score, rbom.grade, rbom.findings, exploit, rbom.tainted
    );

    if findings.is_empty() {
        return;
    }

    let (critical, high, medium, low) = severity_counts(findings);
    println!(
        "Summary: critical={} high={} medium={} low={}",
        critical, high, medium, low
    );

    let groups = group_findings(findings);

    println!("Top risks:");
    for (i, g) in groups.iter().take(5).enumerate() {
        let f = &g.primary;
        let risk = rbom::score_finding(f);
        let exp = format!("{:?}", risk.exploitability).to_ascii_uppercase();
        println!(
            "  #{:<3} {:<9} {:<6} {:<26} {}:{} ({}×)",
            i + 1,
            severity_str(f.severity),
            exp,
            f.rule_id,
            shorten_path(&f.location.path, 44),
            f.location.line,
            g.occurrences
        );
    }
    println!();

    println!(
        "{:<4}  {:<4}  {:<6}  {:<6}  {:<9}  {:<9}  {:<34}  {:<28}  {}",
        "#", "OCC", "LINE", "COL", "SEV", "EXPLOIT", "RULE", "DESC", "FILE"
    );

    for (i, g) in groups.iter().enumerate() {
        let f = &g.primary;
        let risk = rbom::score_finding(f);
        let sev = severity_str(f.severity);
        let exploit = format!("{:?}", risk.exploitability).to_ascii_uppercase();

        let sev_disp = if use_color {
            color_severity(sev, f.severity)
        } else {
            sev.to_string()
        };
        let exploit_disp = if use_color {
            color_exploitability(&exploit, risk.exploitability)
        } else {
            exploit.clone()
        };

        let file = shorten_path(&f.location.path, 52);
        let desc = shorten_text(rule_description(&f.rule_id), 28);
        println!(
            "{:<4}  {:<4}  {:<6}  {:<6}  {:<9}  {:<9}  {:<34}  {:<28}  {}",
            i + 1,
            g.occurrences,
            f.location.line,
            f.location.column,
            sev_disp,
            exploit_disp,
            f.rule_id,
            desc,
            file,
        );
    }

    println!();
    for (i, g) in groups.iter().enumerate() {
        let f = &g.primary;
        println!("#{} {} ({} occurrences)", i + 1, f.rule_id, g.occurrences);
        println!("  Why this matters: {}", why_this_matters(&f.rule_id));
        println!("  Suggested fix: {}", fix_suggestion(f));
        println!(
            "  Primary: {}:{}:{}",
            f.location.path, f.location.line, f.location.column
        );
        if g.occurrences > 1 {
            println!("  Occurrences:");
            for loc in g.locations.iter().take(10) {
                println!("    - {}:{}:{}", loc.path, loc.line, loc.column);
            }
            if g.locations.len() > 10 {
                println!("    - ... ({} more)", g.locations.len() - 10);
            }
        }
        if let Some(p) = &f.path {
            println!("  Path: {}", p.join(" -> "));
        }
        println!();
    }
}

fn severity_str(s: sast_core::Severity) -> &'static str {
    match s {
        sast_core::Severity::Low => "LOW",
        sast_core::Severity::Medium => "MEDIUM",
        sast_core::Severity::High => "HIGH",
        sast_core::Severity::Critical => "CRITICAL",
    }
}

fn print_report(rbom: &rbom::RbomScore, findings: &[sast_core::Finding]) {
    let exploit = format!("{:?}", rbom.exploitability).to_ascii_uppercase();

    let mut low = 0usize;
    let mut medium = 0usize;
    let mut high = 0usize;
    let mut critical = 0usize;
    for f in findings {
        match f.severity {
            sast_core::Severity::Low => low += 1,
            sast_core::Severity::Medium => medium += 1,
            sast_core::Severity::High => high += 1,
            sast_core::Severity::Critical => critical += 1,
        }
    }

    println!("# SAST Report\n");
    println!("## Summary\n");
    println!(
        "- RBOM: score={} grade={} findings={} exploitability={} tainted={}",
        rbom.score, rbom.grade, rbom.findings, exploit, rbom.tainted
    );
    println!(
        "- Severities: critical={} high={} medium={} low={}\n",
        critical, high, medium, low
    );

    let groups = group_findings(findings);

    println!("## Top Risks\n");
    if findings.is_empty() {
        println!("- No findings.\n");
    } else {
        println!("| Rank | Occurrences | Severity | Exploitability | Rule | Primary |");
        println!("|---:|---:|---|---|---|---|");
        for (i, g) in groups.iter().take(10).enumerate() {
            let f = &g.primary;
            let risk = rbom::score_finding(f);
            let sev = severity_str(f.severity);
            let exp = format!("{:?}", risk.exploitability).to_ascii_uppercase();
            println!(
                "| {} | {} | {} | {} | `{}` | `{}` |",
                i + 1,
                g.occurrences,
                sev,
                exp,
                f.rule_id,
                format!("{}:{}:{}", f.location.path, f.location.line, f.location.column)
            );
        }
        println!();
    }

    println!("## Findings\n");
    for (i, g) in groups.iter().enumerate() {
        let f = &g.primary;
        let risk = rbom::score_finding(f);
        let sev = severity_str(f.severity);
        let exp = format!("{:?}", risk.exploitability).to_ascii_uppercase();

        println!(
            "### {}. `{}` ({}, {} occurrences)\n",
            i + 1,
            f.rule_id,
            sev,
            g.occurrences
        );
        println!(
            "- Primary: `{}`",
            format!("{}:{}:{}", f.location.path, f.location.line, f.location.column)
        );
        if g.occurrences > 1 {
            println!("- Occurrences:");
            for loc in g.locations.iter().take(20) {
                println!("  - `{}`", format!("{}:{}:{}", loc.path, loc.line, loc.column));
            }
            if g.locations.len() > 20 {
                println!("  - `... ({} more)`", g.locations.len() - 20);
            }
        }
        println!("- Exploitability: {}", exp);
        println!("- Tainted (risk): {}", risk.tainted);
        if f.conditional {
            println!("- Conditional: true");
        }
        if f.guarded {
            println!("- Guarded: true");
        }
        if let Some(r) = &f.reason {
            println!("- Reason: {}", r);
        }
        println!();

        println!("**Explanation**");
        println!("{}", f.message);
        println!();

        println!("**Why this matters**");
        println!("{}", why_this_matters(&f.rule_id));
        println!();

        println!("**Suggested fix**");
        println!("{}", fix_suggestion(f));
        if let Some(vc) = &f.vuln_context {
            let mut parts = Vec::new();
            if let Some(sink) = &vc.sink {
                parts.push(format!("sink=`{sink}`"));
            }
            if let Some(src) = &vc.input_source {
                parts.push(format!("source=`{src}`"));
            }
            if let Some(bs) = vc.buffer_size {
                parts.push(format!("buffer_size=`{bs}`"));
            }
            if let Some(pos) = &vc.arg_positions {
                parts.push(format!("arg_positions=`{pos:?}`"));
            }
            if !parts.is_empty() {
                println!("\nContext: {}", parts.join(", "));
            }
        }
        println!();

        if let Some(p) = &f.path {
            println!("**Dataflow Path**");
            println!("`{}`\n", p.join(" -> "));
        }

        if let Some(snippet) = &f.snippet {
            println!("**Snippet**");
            println!("```c\n{}\n```\n", snippet);
        }

        if let Some(poc) = &f.poc {
            println!("**PoC**");
            println!("- Type: `{}`", poc.r#type);
            println!("- Description: {}", poc.description);
            println!("- Payload:");
            println!("```text\n{}\n```\n", poc.payload);
        }
    }
}

fn severity_counts(findings: &[sast_core::Finding]) -> (usize, usize, usize, usize) {
    let mut low = 0usize;
    let mut medium = 0usize;
    let mut high = 0usize;
    let mut critical = 0usize;
    for f in findings {
        match f.severity {
            sast_core::Severity::Low => low += 1,
            sast_core::Severity::Medium => medium += 1,
            sast_core::Severity::High => high += 1,
            sast_core::Severity::Critical => critical += 1,
        }
    }
    (critical, high, medium, low)
}

#[derive(Debug, Clone)]
struct FindingGroup {
    primary: sast_core::Finding,
    occurrences: usize,
    locations: Vec<sast_core::Location>,
}

fn group_findings(findings: &[sast_core::Finding]) -> Vec<FindingGroup> {
    use std::collections::HashMap;

    #[derive(Debug, Clone, PartialEq, Eq, Hash)]
    struct Key {
        rule_id: String,
        file: String,
        snippet_pat: String,
    }

    let mut out: Vec<FindingGroup> = Vec::new();
    let mut idx: HashMap<Key, usize> = HashMap::new();

    for f in findings {
        let snippet_pat = normalize_snippet_pattern(f.snippet.as_deref().unwrap_or(""));
        let key = Key {
            rule_id: f.rule_id.clone(),
            file: f.location.path.clone(),
            snippet_pat,
        };
        if let Some(&i) = idx.get(&key) {
            out[i].occurrences += 1;
            out[i].locations.push(f.location.clone());
        } else {
            let i = out.len();
            idx.insert(key, i);
            out.push(FindingGroup {
                primary: f.clone(),
                occurrences: 1,
                locations: vec![f.location.clone()],
            });
        }
    }

    out
}

fn normalize_snippet_pattern(snippet: &str) -> String {
    let s = snippet.split_whitespace().collect::<Vec<_>>().join(" ");
    if s.is_empty() {
        return "".to_string();
    }

    // Preserve leading callee `foo(` if present.
    let mut i = 0usize;
    while i < s.len() && s.as_bytes()[i].is_ascii_whitespace() {
        i += 1;
    }
    let start = i;
    while i < s.len() {
        let b = s.as_bytes()[i];
        if (b as char).is_ascii_alphanumeric() || b == b'_' {
            i += 1;
        } else {
            break;
        }
    }
    let callee = if i > start && i < s.len() && s.as_bytes()[i] == b'(' {
        &s[start..i]
    } else {
        ""
    };

    let mut out = String::new();
    if !callee.is_empty() {
        out.push_str(callee);
    }

    let mut j = if !callee.is_empty() { i } else { 0 };
    while j < s.len() {
        let ch = s.as_bytes()[j] as char;

        // Strings: "...".
        if ch == '"' {
            out.push_str("\"<str>\"");
            j += 1;
            while j < s.len() {
                let c = s.as_bytes()[j] as char;
                if c == '\\' {
                    j = (j + 2).min(s.len());
                    continue;
                }
                if c == '"' {
                    j += 1;
                    break;
                }
                j += 1;
            }
            continue;
        }
        // Chars: 'a'.
        if ch == '\'' {
            out.push_str("'<chr>'");
            j += 1;
            while j < s.len() {
                let c = s.as_bytes()[j] as char;
                if c == '\\' {
                    j = (j + 2).min(s.len());
                    continue;
                }
                if c == '\'' {
                    j += 1;
                    break;
                }
                j += 1;
            }
            continue;
        }

        // Numbers.
        if ch.is_ascii_digit() {
            out.push_str("<num>");
            j += 1;
            while j < s.len() {
                let c = s.as_bytes()[j] as char;
                if c.is_ascii_alphanumeric() || c == 'x' || c == 'X' {
                    j += 1;
                } else {
                    break;
                }
            }
            continue;
        }

        // Identifiers (except the preserved callee at the start).
        if ch.is_ascii_alphabetic() || ch == '_' {
            out.push_str("<id>");
            j += 1;
            while j < s.len() {
                let c = s.as_bytes()[j] as char;
                if c.is_ascii_alphanumeric() || c == '_' {
                    j += 1;
                } else {
                    break;
                }
            }
            continue;
        }

        out.push(ch);
        j += 1;
    }

    // Keep pattern bounded to avoid pathological sizes.
    if out.len() > 200 {
        format!("{}…", &out[..199])
    } else {
        out
    }
}

fn shorten_path(path: &str, max: usize) -> String {
    if path.len() <= max {
        return path.to_string();
    }
    let tail_len = max.saturating_sub(3);
    format!("...{}", &path[path.len().saturating_sub(tail_len)..])
}

fn shorten_text(s: &str, max: usize) -> String {
    let collapsed = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.len() <= max {
        return collapsed;
    }
    let keep = max.saturating_sub(1);
    format!("{}…", &collapsed[..keep])
}

fn rule_description(rule_id: &str) -> &'static str {
    match rule_id {
        "c.format_string" => "Untrusted format string",
        "c.command_injection" => "Command execution sink",
        "c.buffer_overflow.pointer_arithmetic" => "Overflow risk (offset dst)",
        "c.buffer_overflow" => "Unsafe copy/format",
        "c.use_after_free" => "Use after free",
        "c.double_free" => "Double free",
        _ => "Security finding",
    }
}

fn why_this_matters(rule_id: &str) -> &'static str {
    match rule_id {
        "c.format_string" => "An attacker-controlled format string can read memory, crash the program, and sometimes write memory (e.g., %n), which can lead to code execution.",
        "c.command_injection" => "If user-controlled data reaches a command execution API, an attacker may run arbitrary OS commands on the host.",
        "c.buffer_overflow.pointer_arithmetic" | "c.buffer_overflow" => "Buffer overflows can corrupt memory, causing crashes and potentially enabling code execution or privilege escalation.",
        "c.use_after_free" => "Using freed memory is undefined behavior and can lead to crashes, memory corruption, and exploitation.",
        "c.double_free" => "Freeing the same pointer twice is undefined behavior and can corrupt allocator state, sometimes enabling exploitation.",
        _ => "This pattern can lead to a security vulnerability depending on runtime inputs and program state.",
    }
}

fn fix_suggestion(f: &sast_core::Finding) -> String {
    let sink = f
        .vuln_context
        .as_ref()
        .and_then(|v| v.sink.as_deref())
        .unwrap_or("");

    if sink == "printf" || sink == "fprintf" || sink == "sprintf" || sink == "vsprintf" {
        if f.rule_id == "c.format_string" {
            return "Ensure the format string is a literal and pass user input as data (e.g., `printf(\"%s\", input)` / `snprintf(buf, cap, \"%s\", input)`)."
                .to_string();
        }
    }

    if sink == "sprintf" || sink == "vsprintf" {
        if f.rule_id == "c.buffer_overflow.pointer_arithmetic" {
            return "Prefer `snprintf(dst, remaining, ...)` and validate `offset + required_len < capacity` before writing to `buf+offset`.".to_string();
        }
        return "Prefer `snprintf` (or `vsnprintf`) with an explicit buffer size, and ensure the format string is a literal (e.g., `\"%s\"`).".to_string();
    }
    if f.rule_id == "c.buffer_overflow.pointer_arithmetic" {
        return "Validate bounds for pointer arithmetic destinations (offset + length <= buffer_size) before copying/writing.".to_string();
    }
    if sink == "strcpy" || sink == "strcat" || sink == "gets" {
        return "Avoid unbounded copies; use bounded alternatives (`strncpy/strlcpy`, `snprintf`, or explicit length checks) and ensure destination size is respected.".to_string();
    }
    if sink == "system" || sink == "popen" || sink.starts_with("exec") {
        return "Avoid shell-based APIs. Prefer `execve`/`posix_spawn` with fixed argv, or strictly validate/whitelist input.".to_string();
    }
    if f.rule_id == "c.use_after_free" {
        return "Do not use a pointer after `free()`. Clear it (`p = NULL`) and ensure ownership/lifetimes prevent reuse.".to_string();
    }
    if f.rule_id == "c.double_free" {
        return "Ensure each allocation is freed exactly once. Clear pointers after free (`p = NULL`) and avoid duplicated ownership.".to_string();
    }
    "Apply input validation and safer APIs for this pattern.".to_string()
}

fn color_severity(label: &str, sev: sast_core::Severity) -> String {
    let (prefix, suffix) = match sev {
        sast_core::Severity::Critical => ("\x1b[1;31m", "\x1b[0m"),
        sast_core::Severity::High => ("\x1b[1;31m", "\x1b[0m"),
        sast_core::Severity::Medium => ("\x1b[1;33m", "\x1b[0m"),
        sast_core::Severity::Low => ("\x1b[32m", "\x1b[0m"),
    };
    format!("{prefix}{label}{suffix}")
}

fn color_exploitability(label: &str, exp: rbom::Exploitability) -> String {
    let (prefix, suffix) = match exp {
        rbom::Exploitability::High => ("\x1b[1;31m", "\x1b[0m"),
        rbom::Exploitability::Medium => ("\x1b[1;33m", "\x1b[0m"),
        rbom::Exploitability::Low => ("\x1b[32m", "\x1b[0m"),
    };
    format!("{prefix}{label}{suffix}")
}

fn sort_and_rank(findings: &mut Vec<sast_core::Finding>) {
    fn exp_rank(e: rbom::Exploitability) -> u8 {
        match e {
            rbom::Exploitability::High => 2,
            rbom::Exploitability::Medium => 1,
            rbom::Exploitability::Low => 0,
        }
    }

    fn sev_rank(s: sast_core::Severity) -> u8 {
        match s {
            sast_core::Severity::Critical => 3,
            sast_core::Severity::High => 2,
            sast_core::Severity::Medium => 1,
            sast_core::Severity::Low => 0,
        }
    }

    #[derive(Clone, Copy, Debug)]
    struct Key {
        exp: u8,
        sev: u8,
        tainted: u8,
    }

    let mut keyed: Vec<(Key, sast_core::Finding)> = findings
        .drain(..)
        .map(|f| {
            let s = rbom::score_finding(&f);
            let key = Key {
                exp: exp_rank(s.exploitability),
                sev: sev_rank(f.severity),
                tainted: if s.tainted { 1 } else { 0 },
            };
            (key, f)
        })
        .collect();

    keyed.sort_by(|(ka, fa), (kb, fb)| {
        // exploitability (desc), severity (desc), tainted first (desc), then deterministic tiebreakers
        kb.exp
            .cmp(&ka.exp)
            .then_with(|| kb.sev.cmp(&ka.sev))
            .then_with(|| kb.tainted.cmp(&ka.tainted))
            .then_with(|| fa.location.path.cmp(&fb.location.path))
            .then_with(|| fa.location.line.cmp(&fb.location.line))
            .then_with(|| fa.location.column.cmp(&fb.location.column))
            .then_with(|| fa.rule_id.cmp(&fb.rule_id))
    });

    *findings = keyed.into_iter().map(|(_, f)| f).collect();
    for (i, f) in findings.iter_mut().enumerate() {
        f.rank = i + 1;
    }
}

#[derive(Debug, Clone)]
struct BaselineDiff {
    new: Vec<sast_core::Finding>,
    fixed: Vec<sast_core::Finding>,
    unchanged: Vec<sast_core::Finding>,
}

fn compare_findings(old: &[sast_core::Finding], cur: &[sast_core::Finding]) -> BaselineDiff {
    use std::collections::{BTreeMap, BTreeSet};

    type Key = (String, String, usize);
    fn k(f: &sast_core::Finding) -> Key {
        (f.rule_id.clone(), f.location.path.clone(), f.location.line)
    }

    let mut old_map: BTreeMap<Key, &sast_core::Finding> = BTreeMap::new();
    for f in old {
        old_map.entry(k(f)).or_insert(f);
    }
    let mut cur_map: BTreeMap<Key, &sast_core::Finding> = BTreeMap::new();
    for f in cur {
        cur_map.entry(k(f)).or_insert(f);
    }

    let old_keys: BTreeSet<Key> = old_map.keys().cloned().collect();
    let cur_keys: BTreeSet<Key> = cur_map.keys().cloned().collect();

    let mut new = Vec::new();
    let mut fixed = Vec::new();
    let mut unchanged = Vec::new();

    for key in cur_keys.difference(&old_keys) {
        if let Some(f) = cur_map.get(key) {
            new.push((*f).clone());
        }
    }
    for key in old_keys.difference(&cur_keys) {
        if let Some(f) = old_map.get(key) {
            let mut ff = (*f).clone();
            ff.rank = 0;
            fixed.push(ff);
        }
    }
    for key in cur_keys.intersection(&old_keys) {
        if let Some(f) = cur_map.get(key) {
            unchanged.push((*f).clone());
        }
    }

    BaselineDiff { new, fixed, unchanged }
}

fn load_baseline_findings(path: &PathBuf) -> Result<Vec<sast_core::Finding>, String> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let raw = fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let v: Value = serde_json::from_str(&raw).map_err(|e| format!("{}: {e}", path.display()))?;
    if v.is_array() {
        serde_json::from_value(v).map_err(|e| format!("{}: {e}", path.display()))
    } else if let Some(arr) = v.get("findings") {
        serde_json::from_value(arr.clone()).map_err(|e| format!("{}: {e}", path.display()))
    } else {
        Err(format!(
            "{}: baseline JSON must be an array of findings or an object with a `findings` field",
            path.display()
        ))
    }
}

fn save_baseline(path: &PathBuf, findings: &[sast_core::Finding], rbom: &rbom::RbomScore) -> Result<(), String> {
    let out = serde_json::json!({
        "findings": findings,
        "rbom": rbom,
    });
    let s = serde_json::to_string_pretty(&out).map_err(|e| e.to_string())?;
    fs::write(path, s).map_err(|e| format!("{}: {e}", path.display()))
}
