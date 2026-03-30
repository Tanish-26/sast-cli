use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use sast_core::{poc, Confidence, Language};
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

    /// Emit SARIF v2.1.0 (GitHub code scanning compatible)
    #[arg(long, conflicts_with_all = ["json", "summary", "table", "report", "baseline"])]
    sarif: bool,

    /// Compare against a baseline JSON file (also updates baseline to current scan)
    #[arg(long)]
    baseline: Option<PathBuf>,

    /// Force language for single-file scans: javascript|c|cpp
    #[arg(long)]
    language: Option<String>,

    /// Show only validated, high-confidence findings
    #[arg(long)]
    validated_only: bool,

    /// Minimum confidence to include: low|medium|high
    #[arg(long, value_parser = ["low", "medium", "high"])]
    min_confidence: Option<String>,

    /// Show dataflow path (table/report output)
    #[arg(long)]
    show_path: bool,

    /// Show validation notes (table/report output)
    #[arg(long)]
    show_notes: bool,

    /// Sort by exploitability score descending
    #[arg(long)]
    sort_by_exploitability: bool,

    /// Return only the top N findings after sorting/filtering
    #[arg(long)]
    top: Option<usize>,

    /// Debug validator (prints CFG/path reasoning to stderr)
    #[arg(long)]
    debug_validator: bool,
}

fn main() -> ExitCode {
    let args = Args::parse();
    if args.debug_validator {
        std::env::set_var("SAST_VALIDATOR_DEBUG", "1");
    }

    let mut findings = Vec::new();
    let mut files = Vec::new();
    let mut ast_map: sast_validator::AstMap = Default::default();

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

        if let Some(ast) = sast_validator::parse_file(&path, &src, lang.clone()) {
            ast_map.insert(path.clone(), ast);
        }

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

    let (c_family, mut non_c_family): (Vec<_>, Vec<_>) =
        findings.into_iter().partition(|f| is_c_family_path(&f.location.path));
    let call_graph = sast_validator::build_call_graph(&ast_map);
    let mut findings = sast_validator::validate_findings(c_family, &ast_map, &call_graph);
    findings.append(&mut non_c_family);

    attach_exploitability(&mut findings);

    let before_filter = findings.len();
    let mut filter_notes: Vec<&'static str> = Vec::new();
    apply_filters(&mut findings, &args, &mut filter_notes);

    poc::attach(&mut findings);
    detect_exploit_chains(&mut findings);
    sort_and_rank(&mut findings, args.sort_by_exploitability);

    if let Some(n) = args.top {
        if findings.len() > n {
            findings.truncate(n);
            filter_notes.push("top_n");
        }
    }

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
        let out = json_output(&findings, &rbom);
        match serde_json::to_string_pretty(&out) {
            Ok(s) => println!("{s}"),
            Err(e) => {
                eprintln!("{e}");
                return ExitCode::from(2);
            }
        }
    } else if args.sarif {
        let out = sarif_output(&findings);
        match serde_json::to_string_pretty(&out) {
            Ok(s) => println!("{s}"),
            Err(e) => {
                eprintln!("{e}");
                return ExitCode::from(2);
            }
        }
    } else if args.report {
        if before_filter != findings.len() && !filter_notes.is_empty() {
            println!("Filtered results: {}", filter_message(&filter_notes));
            println!();
        }
        print_report(&rbom, &findings, args.show_path, args.show_notes);
    } else if args.summary {
        if before_filter != findings.len() && !filter_notes.is_empty() {
            println!("Filtered results: {}", filter_message(&filter_notes));
        }
        print_summary(&rbom, &findings);
    } else {
        // Default: table output (or explicit --table).
        if before_filter != findings.len() && !filter_notes.is_empty() {
            println!("Filtered results: {}", filter_message(&filter_notes));
            println!();
        }
        print_table(&rbom, &findings, args.show_path, args.show_notes);
    }

    if findings.is_empty() { ExitCode::SUCCESS } else { ExitCode::from(1) }
}

fn is_c_family_path(path: &str) -> bool {
    let p = path.to_ascii_lowercase();
    p.ends_with(".c")
        || p.ends_with(".h")
        || p.ends_with(".cc")
        || p.ends_with(".cpp")
        || p.ends_with(".cxx")
        || p.ends_with(".hh")
        || p.ends_with(".hpp")
        || p.ends_with(".hxx")
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
    let mut validated = 0usize;
    let mut high_confidence = 0usize;
    for f in findings {
        match f.severity {
            sast_core::Severity::Low => low += 1,
            sast_core::Severity::Medium => medium += 1,
            sast_core::Severity::High => high += 1,
            sast_core::Severity::Critical => critical += 1,
        }
        if f.confidence == Some(Confidence::High) {
            high_confidence += 1;
        }
        if is_validated(f) {
            validated += 1;
        }
    }

    let exploit = format!("{:?}", rbom.exploitability).to_ascii_uppercase();
    println!(
        "RBOM: score={} grade={} findings={} exploitability={} tainted={}",
        rbom.score, rbom.grade, rbom.findings, exploit, rbom.tainted
    );
    println!(
        "Validation: validated={} high_confidence={}",
        validated, high_confidence
    );
    println!(
        "Findings: critical={} high={} medium={} low={}",
        critical, high, medium, low
    );
}

fn print_table(rbom: &rbom::RbomScore, findings: &[sast_core::Finding], show_path: bool, show_notes: bool) {
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
    let (validated, high_confidence) = validation_counts(findings);
    println!(
        "Summary: critical={} high={} medium={} low={} validated={} high_confidence={}",
        critical, high, medium, low, validated, high_confidence
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
        "{:<4}  {:<4}  {:<6}  {:<6}  {:<9}  {:<6}  {:<9}  {:<34}  {:<28}  {}",
        "#", "OCC", "LINE", "COL", "SEV", "CONF", "EXPLOIT", "RULE", "DESC", "FILE"
    );

    for (i, g) in groups.iter().enumerate() {
        let f = &g.primary;
        let sev = severity_str(f.severity);
        let conf = confidence_str(f);
        let exploit = f
            .exploitability_level
            .as_deref()
            .unwrap_or("unknown")
            .to_ascii_uppercase();

        let sev_disp = if use_color {
            color_severity(sev, f.severity)
        } else {
            sev.to_string()
        };
        let exploit_disp = if use_color { color_exploitability_level(&exploit) } else { exploit.clone() };

        let file = shorten_path(&f.location.path, 52);
        let desc = shorten_text(rule_description(&f.rule_id), 28);
        println!(
            "{:<4}  {:<4}  {:<6}  {:<6}  {:<9}  {:<6}  {:<9}  {:<34}  {:<28}  {}",
            i + 1,
            g.occurrences,
            f.location.line,
            f.location.column,
            sev_disp,
            conf,
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
        if let Some(chain) = &f.exploit_chain {
            println!("  Exploit chain: {}", chain.join(" -> "));
        }
        if let Some(score) = f.exploitability_score {
            let lvl = f.exploitability_level.as_deref().unwrap_or("unknown");
            println!("  Exploitability: {} ({score})", lvl.to_ascii_uppercase());
        }
        if show_path {
            if let Some(p) = &f.validated_path {
                println!("  Path: {}", p.join(" -> "));
            } else if let Some(p) = &f.path {
                println!("  Path: {}", p.join(" -> "));
            }
        }
        if show_notes {
            if let Some(ns) = &f.validation_notes {
                if !ns.is_empty() {
                    println!("  Notes:");
                    for n in ns {
                        println!("    - {}", n);
                    }
                }
            }
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

fn print_report(rbom: &rbom::RbomScore, findings: &[sast_core::Finding], show_path: bool, show_notes: bool) {
    let exploit = format!("{:?}", rbom.exploitability).to_ascii_uppercase();

    let mut low = 0usize;
    let mut medium = 0usize;
    let mut high = 0usize;
    let mut critical = 0usize;
    let (validated, high_confidence) = validation_counts(findings);
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
    println!("- Validation: validated={} high_confidence={}", validated, high_confidence);
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
        let sev = severity_str(f.severity);
        let exp = f
            .exploitability_level
            .as_deref()
            .unwrap_or("unknown")
            .to_ascii_uppercase();

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
        if let Some(score) = f.exploitability_score {
            println!("- Exploitability score: {}", score);
        }
        println!("- Tainted (risk): {}", f.tainted || f.implicit_risk);
        if let Some(c) = f.confidence {
            println!("- Confidence: {}", format!("{c:?}").to_ascii_uppercase());
        }
        if is_validated(f) {
            println!("- Validated: true");
        }
        if f.conditional {
            println!("- Conditional: true");
        }
        if f.guarded {
            println!("- Guarded: true");
        }
        if let Some(r) = &f.reason {
            println!("- Reason: {}", r);
        }
        if let Some(chain) = &f.exploit_chain {
            println!("- Exploit chain: `{}`", chain.join(" -> "));
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

        if show_notes {
            if let Some(ns) = &f.validation_notes {
                if !ns.is_empty() {
                    println!("**Validation Notes**");
                    for n in ns {
                        println!("- {}", n);
                    }
                    println!();
                }
            }
        }

        if show_path {
            if let Some(p) = &f.validated_path {
                println!("**Validated Path**");
                println!("`{}`\n", p.join(" -> "));
            } else if let Some(p) = &f.path {
                println!("**Dataflow Path**");
                println!("`{}`\n", p.join(" -> "));
            }
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

fn detect_exploit_chains(findings: &mut [sast_core::Finding]) {
    use std::collections::{BTreeSet, HashMap};

    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    enum Cat {
        BufferOverflow,
        PointerOverwrite,
        UseAfterFree,
    }

    fn cat_for(rule_id: &str) -> Option<Cat> {
        if rule_id == "c.buffer_overflow.pointer_arithmetic" {
            return Some(Cat::PointerOverwrite);
        }
        if rule_id.starts_with("c.buffer_overflow") {
            return Some(Cat::BufferOverflow);
        }
        if rule_id == "c.use_after_free" {
            return Some(Cat::UseAfterFree);
        }
        None
    }

    fn cat_name(c: Cat) -> &'static str {
        match c {
            Cat::BufferOverflow => "buffer_overflow",
            Cat::PointerOverwrite => "pointer_overwrite",
            Cat::UseAfterFree => "use_after_free",
        }
    }

    fn first_ident(s: &str) -> Option<String> {
        let bytes = s.as_bytes();
        let mut i = 0usize;
        while i < bytes.len() {
            let ch = bytes[i] as char;
            if ch.is_ascii_alphabetic() || ch == '_' {
                let start = i;
                i += 1;
                while i < bytes.len() {
                    let c = bytes[i] as char;
                    if c.is_ascii_alphanumeric() || c == '_' {
                        i += 1;
                    } else {
                        break;
                    }
                }
                return Some(s[start..i].to_string());
            }
            i += 1;
        }
        None
    }

    fn is_noise(tok: &str, f: &sast_core::Finding) -> bool {
        if tok.is_empty() {
            return true;
        }
        if let Some(vc) = &f.vuln_context {
            if vc.sink.as_deref() == Some(tok) {
                return true;
            }
            if vc.input_source.as_deref() == Some(tok) {
                return true;
            }
        }
        matches!(
            tok,
            "argv"
                | "getenv"
                | "read"
                | "recv"
                | "scanf"
                | "sprintf"
                | "snprintf"
                | "printf"
                | "strcpy"
                | "strcat"
                | "gets"
                | "system"
                | "free"
                | "use"
        )
    }

    fn vars_for(f: &sast_core::Finding) -> BTreeSet<String> {
        let mut out = BTreeSet::new();
        if let Some(steps) = &f.path {
            for s in steps {
                if let Some(id) = first_ident(s) {
                    if !is_noise(&id, f) {
                        out.insert(id);
                    }
                }
            }
        }
        out
    }

    let mut var_cats: HashMap<String, BTreeSet<Cat>> = HashMap::new();
    let mut var_idxs: HashMap<String, Vec<usize>> = HashMap::new();

    for (idx, f) in findings.iter().enumerate() {
        let Some(cat) = cat_for(&f.rule_id) else { continue };
        for v in vars_for(f) {
            var_cats.entry(v.clone()).or_default().insert(cat);
            var_idxs.entry(v).or_default().push(idx);
        }
    }

    for (var, cats) in &var_cats {
        // Build a simple ordered chain from the categories we observed for this variable.
        let mut chain: Vec<&'static str> = Vec::new();
        // Pointer-overwrite implies an overflow stage as well.
        if cats.contains(&Cat::BufferOverflow) || cats.contains(&Cat::PointerOverwrite) {
            chain.push(cat_name(Cat::BufferOverflow));
        }
        if cats.contains(&Cat::PointerOverwrite) {
            chain.push(cat_name(Cat::PointerOverwrite));
        }
        if cats.contains(&Cat::UseAfterFree) {
            chain.push(cat_name(Cat::UseAfterFree));
        }

        // Require multiple distinct stages to consider it a chain.
        if chain.len() < 2 {
            continue;
        }

        let chain_owned = chain.into_iter().map(str::to_string).collect::<Vec<_>>();
        if let Some(idxs) = var_idxs.get(var) {
            for &i in idxs {
                let cur_len = findings[i].exploit_chain.as_ref().map(|c| c.len()).unwrap_or(0);
                if chain_owned.len() > cur_len {
                    findings[i].exploit_chain = Some(chain_owned.clone());
                }
            }
        }
    }
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

fn sort_and_rank(findings: &mut Vec<sast_core::Finding>, sort_by_exploitability: bool) {
    fn sev_rank(s: sast_core::Severity) -> u8 {
        match s {
            sast_core::Severity::Critical => 3,
            sast_core::Severity::High => 2,
            sast_core::Severity::Medium => 1,
            sast_core::Severity::Low => 0,
        }
    }

    findings.sort_by(|a, b| {
        let ascore = a.exploitability_score.unwrap_or(0);
        let bscore = b.exploitability_score.unwrap_or(0);
        let aconf = conf_rank(a.confidence);
        let bconf = conf_rank(b.confidence);
        let ataint = if a.tainted || a.implicit_risk { 1 } else { 0 };
        let btaint = if b.tainted || b.implicit_risk { 1 } else { 0 };

        if sort_by_exploitability {
            bscore
                .cmp(&ascore)
                .then_with(|| sev_rank(b.severity).cmp(&sev_rank(a.severity)))
                .then_with(|| btaint.cmp(&ataint))
                .then_with(|| bconf.cmp(&aconf))
        } else {
            sev_rank(b.severity)
                .cmp(&sev_rank(a.severity))
                .then_with(|| bscore.cmp(&ascore))
                .then_with(|| btaint.cmp(&ataint))
                .then_with(|| bconf.cmp(&aconf))
        }
        .then_with(|| a.location.path.cmp(&b.location.path))
        .then_with(|| a.location.line.cmp(&b.location.line))
        .then_with(|| a.location.column.cmp(&b.location.column))
        .then_with(|| a.rule_id.cmp(&b.rule_id))
    });

    for (i, f) in findings.iter_mut().enumerate() {
        f.rank = i + 1;
    }
}

fn conf_rank(c: Option<Confidence>) -> u8 {
    match c.unwrap_or(Confidence::Medium) {
        Confidence::Low => 0,
        Confidence::Medium => 1,
        Confidence::High => 2,
    }
}

fn confidence_str(f: &sast_core::Finding) -> &'static str {
    match f.confidence.unwrap_or(Confidence::Medium) {
        Confidence::Low => "LOW",
        Confidence::Medium => "MED",
        Confidence::High => "HIGH",
    }
}

fn is_validated(f: &sast_core::Finding) -> bool {
    f.validated
}

fn validation_counts(findings: &[sast_core::Finding]) -> (usize, usize) {
    let mut validated = 0usize;
    let mut high_conf = 0usize;
    for f in findings {
        if f.confidence == Some(Confidence::High) {
            high_conf += 1;
        }
        if is_validated(f) {
            validated += 1;
        }
    }
    (validated, high_conf)
}

fn color_exploitability_level(level: &str) -> String {
    let (prefix, suffix) = match level {
        "HIGH" => ("\x1b[1;31m", "\x1b[0m"),
        "MEDIUM" => ("\x1b[1;33m", "\x1b[0m"),
        "LOW" => ("\x1b[32m", "\x1b[0m"),
        _ => ("\x1b[0m", "\x1b[0m"),
    };
    format!("{prefix}{level}{suffix}")
}

fn attach_exploitability(findings: &mut [sast_core::Finding]) {
    for f in findings {
        let (score, level) = exploitability_for(f);
        f.exploitability_score = Some(score);
        f.exploitability_level = Some(level);
    }
}

fn exploitability_for(f: &sast_core::Finding) -> (u8, String) {
    let mut score: i32 = 0;
    match f.rule_id.as_str() {
        rid if rid.starts_with("c.buffer_overflow") => {
            score += 30;
            if rid.contains("pointer_arithmetic") || f.implicit_risk {
                score += 30;
            }
            if !f.guarded {
                score += 20;
            }
            if f.tainted {
                score += 20;
            }
        }
        "c.format_string" => {
            score += 20;
            if f.tainted {
                score += 40;
            }
            if f.snippet.as_deref().unwrap_or("").contains("%n") {
                score += 30;
            }
        }
        "c.command_injection" => {
            score += 50;
            if f.tainted {
                score += 30;
            }
        }
        "c.use_after_free" => {
            score += 40;
            score += 50;
            if f.path.as_ref().is_some_and(|p| p.len() >= 4) {
                score += 20;
            }
        }
        "c.double_free" => {
            score += 40;
            score += 30;
            if f.path.as_ref().is_some_and(|p| p.len() >= 4) {
                score += 20;
            }
        }
        _ => {
            score += 10;
            if f.implicit_risk {
                score += 10;
            }
            if f.tainted {
                score += 10;
            }
        }
    }

    if score < 0 {
        score = 0;
    }
    if score > 100 {
        score = 100;
    }
    let level = match score {
        0..=30 => "low",
        31..=70 => "medium",
        _ => "high",
    }
    .to_string();
    (score as u8, level)
}

fn apply_filters(findings: &mut Vec<sast_core::Finding>, args: &Args, notes: &mut Vec<&'static str>) {
    let before = findings.len();

    if args.validated_only {
        // TRUE validated findings only: a concrete reconstructed path exists.
        findings.retain(|f| is_validated(f));
        notes.push("validated_only");
    }

    if let Some(min) = args.min_confidence.as_deref() {
        let min_rank = match min {
            "low" => 0u8,
            "medium" => 1u8,
            "high" => 2u8,
            _ => 0u8,
        };
        findings.retain(|f| conf_rank(f.confidence) >= min_rank);
        notes.push("min_confidence");

        // Extra false-positive trimming only at the strictest setting.
        if min == "high" {
            findings.retain(|f| !(f.confidence == Some(Confidence::Low) && f.validated_path.is_none()));
            notes.push("drop_low_no_path");
        }
    }

    if std::env::var("SAST_FILTER_DEBUG").ok().as_deref() == Some("1")
        && (args.validated_only || args.min_confidence.is_some())
    {
        eprintln!("Filter debug: findings {} -> {}", before, findings.len());
    }
}

fn filter_message(notes: &[&'static str]) -> String {
    if notes.contains(&"validated_only") {
        return "showing validated findings only".to_string();
    }
    if notes.contains(&"min_confidence") {
        return "confidence filter applied".to_string();
    }
    if notes.contains(&"top_n") {
        return "top-N filter applied".to_string();
    }
    if notes.contains(&"drop_low_no_path") {
        return "dropping low-confidence unvalidated findings".to_string();
    }
    "filters applied".to_string()
}

fn json_output(findings: &[sast_core::Finding], rbom: &rbom::RbomScore) -> serde_json::Value {
    let (validated, high_confidence) = validation_counts(findings);
    let out_findings: Vec<serde_json::Value> = findings
        .iter()
        .map(|f| {
            let validated_flag = f.validated;
            serde_json::json!({
                "rule": f.rule_id,
                "severity": severity_str(f.severity).to_ascii_lowercase(),
                "confidence": f.confidence.map(|c| format!("{c:?}").to_ascii_lowercase()).unwrap_or("unknown".to_string()),
                "validated": validated_flag,
                "exploitability_score": f.exploitability_score.unwrap_or(0),
                "exploitability_level": f.exploitability_level.clone().unwrap_or_else(|| "unknown".to_string()),
                "path": f.validated_path.clone().or_else(|| f.path.clone()).unwrap_or_default(),
                "notes": f.validation_notes.clone().unwrap_or_default(),
                "location": f.location,
                "snippet": f.snippet,
            })
        })
        .collect();

    serde_json::json!({
        "findings": out_findings,
        "summary": {
            "findings": findings.len(),
            "validated": validated,
            "high_confidence": high_confidence,
        },
        "rbom": rbom,
    })
}

fn sarif_output(findings: &[sast_core::Finding]) -> serde_json::Value {
    use std::collections::BTreeMap;

    // Build a stable rule list and ruleIndex mapping for SARIF.
    let mut rule_map: BTreeMap<String, usize> = BTreeMap::new();
    let mut rules: Vec<serde_json::Value> = Vec::new();
    for f in findings {
        if rule_map.contains_key(&f.rule_id) {
            continue;
        }
        let idx = rules.len();
        rule_map.insert(f.rule_id.clone(), idx);
        rules.push(serde_json::json!({
            "id": f.rule_id,
            "name": f.rule_id,
            "shortDescription": { "text": rule_description(&f.rule_id) },
        }));
    }

    let results: Vec<serde_json::Value> = findings
        .iter()
        .map(|f| {
            let level = match f.severity {
                sast_core::Severity::Critical | sast_core::Severity::High => "error",
                sast_core::Severity::Medium => "warning",
                sast_core::Severity::Low => "note",
            };
            let conf = f
                .confidence
                .map(|c| format!("{c:?}").to_ascii_lowercase())
                .unwrap_or_else(|| "unknown".to_string());
            let sev = severity_str(f.severity).to_ascii_lowercase();
            let exp_score = f.exploitability_score.unwrap_or(0);
            let exp_level = f
                .exploitability_level
                .clone()
                .unwrap_or_else(|| "unknown".to_string());

            let rule_index = rule_map.get(&f.rule_id).copied();

            serde_json::json!({
                "ruleId": f.rule_id,
                "ruleIndex": rule_index,
                "level": level,
                "kind": "fail",
                "message": { "text": f.message },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": f.location.path },
                        "region": {
                            "startLine": f.location.line,
                            "startColumn": f.location.column
                        }
                    }
                }],
                "properties": {
                    "severity": sev,
                    "confidence": conf,
                    "validated": f.validated,
                    "exploitabilityScore": exp_score,
                    "exploitabilityLevel": exp_level
                }
            })
        })
        .collect();

    serde_json::json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "sast-cli",
                    "informationUri": "https://github.com/openai/codex",
                    "rules": rules
                }
            },
            "results": results
        }]
    })
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
