use crate::{Finding, Poc};

/// Attach a basic proof-of-concept payload to each finding (if applicable).
/// This is intentionally lightweight and does not execute anything.
pub fn attach(findings: &mut [Finding]) {
    for f in findings {
        if f.poc.is_some() {
            continue;
        }
        f.poc = generate(f);
    }
}

/// Generate a structured PoC payload for a finding.
///
/// Notes:
/// - Uses `rule_id` + (optional) `vuln_context` fields to pick a payload.
/// - Returns `None` when we don't have a reasonable generic payload.
pub fn generate(f: &Finding) -> Option<Poc> {
    let sink = f
        .vuln_context
        .as_ref()
        .and_then(|v| v.sink.as_deref())
        .unwrap_or("");

    let arg_positions = f
        .vuln_context
        .as_ref()
        .and_then(|v| v.arg_positions.as_ref())
        .map(|v| v.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(", "));

    let mut ctx = String::new();
    if !sink.is_empty() {
        ctx.push_str(&format!("sink={sink} "));
    }
    if let Some(pos) = &arg_positions {
        ctx.push_str(&format!("args=[{pos}] "));
    }
    if !ctx.is_empty() {
        ctx = format!(" ({})", ctx.trim_end());
    }

    if f.rule_id == "c.format_string" {
        return Some(Poc {
            r#type: "format_string".to_string(),
            payload: "%x %x %x %n".to_string(),
            description: format!("Trigger a format string write via uncontrolled format string{ctx}"),
        });
    }

    if f.rule_id == "c.command_injection" {
        return Some(Poc {
            r#type: "command_injection".to_string(),
            payload: "&& id".to_string(),
            description: format!("Attempt command chaining in a shell command sink{ctx}"),
        });
    }

    if f.rule_id == "c.buffer_overflow.pointer_arithmetic" {
        // Offset overflow: some padding to land on the computed destination, then overflow.
        let payload = format!("{}{}", "A".repeat(64), "B".repeat(1000));
        return Some(Poc {
            r#type: "buffer_overflow_offset".to_string(),
            payload,
            description: format!("Overflow an offset destination (padding + overflow){ctx}"),
        });
    }

    if f.rule_id == "c.buffer_overflow" {
        return Some(Poc {
            r#type: "buffer_overflow".to_string(),
            payload: "A".repeat(1000),
            description: format!("Overflow buffer via very large input{ctx}"),
        });
    }

    if f.rule_id == "js.user_input_eval" {
        return Some(Poc {
            r#type: "code_injection".to_string(),
            payload: "alert(1)".to_string(),
            description: "Demonstrate code execution if input reaches eval()".to_string(),
        });
    }

    None
}
