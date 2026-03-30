use serde::{Deserialize, Serialize};
use sast_core::{Finding, Severity};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Exploitability {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RbomScore {
    pub score: u8,
    pub grade: String,
    pub findings: usize,
    pub exploitability: Exploitability,
    pub tainted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingScore {
    pub score: u8,
    pub exploitability: Exploitability,
    pub tainted: bool,
}

pub fn score(findings: &[Finding]) -> RbomScore {
    if findings.is_empty() {
        return RbomScore {
            score: 0,
            grade: grade(0).to_string(),
            findings: 0,
            exploitability: Exploitability::Low,
            tainted: false,
        };
    }

    let mut worst: u8 = 0;
    let mut any_tainted = false;
    let mut worst_exploitability = Exploitability::Low;
    for f in findings {
        let parts = score_parts(f);
        let s = parts.total;
        worst = worst.max(s);
        any_tainted |= parts.risk_tainted;
        worst_exploitability = worst_exploitability.max(parts.exploitability);
    }

    RbomScore {
        score: worst,
        grade: grade(worst).to_string(),
        findings: findings.len(),
        exploitability: worst_exploitability,
        tainted: any_tainted,
    }
}

pub fn score_finding(f: &Finding) -> FindingScore {
    let parts = score_parts(f);
    FindingScore {
        score: parts.total,
        exploitability: parts.exploitability,
        tainted: parts.risk_tainted,
    }
}

#[derive(Debug, Clone)]
struct ScoreParts {
    total: u8,
    exploitability: Exploitability,
    risk_tainted: bool,
}

fn grade(score: u8) -> &'static str {
    match score {
        0..=49 => "A",
        50..=69 => "B",
        70..=89 => "C",
        _ => "D",
    }
}

fn score_parts(f: &Finding) -> ScoreParts {
    // score = base_severity + taint_bonus + memory_risk + exploitability (+/- mitigations)
    let base = base_severity(f.severity);

    let proven_taint = f.tainted;
    let implicit_risk = f.implicit_risk;
    let risk_tainted = proven_taint || implicit_risk;

    // Keep score compatibility: taint bonus only applies when taint is proven.
    let taint_bonus = if proven_taint { 10 } else { 0 };

    let memory_risk = memory_risk_points(&f.rule_id);
    let exploit_bonus = exploitability_points(&f.rule_id);

    let mitigations = mitigation_points(f);

    let raw = base as i32 + taint_bonus + memory_risk + exploit_bonus - mitigations;
    let total = raw.clamp(0, 100) as u8;

    let exploitability = exploitability_level(f, proven_taint, implicit_risk, total);

    // Ensure critical findings always land in the expected range.
    let total = match f.severity {
        Severity::Critical => total.max(90),
        Severity::High => total.clamp(70, 89),
        Severity::Medium => total.clamp(50, 69),
        Severity::Low => total.min(49),
    };

    ScoreParts {
        total,
        exploitability,
        risk_tainted,
    }
}

fn base_severity(sev: Severity) -> u8 {
    match sev {
        Severity::Critical => 95,
        Severity::High => 78,
        Severity::Medium => 60,
        Severity::Low => 35,
    }
}

fn memory_risk_points(rule_id: &str) -> i32 {
    if rule_id.starts_with("c.buffer_overflow")
        || rule_id == "c.use_after_free"
        || rule_id == "c.double_free"
    {
        10
    } else {
        0
    }
}

fn exploitability_points(rule_id: &str) -> i32 {
    if rule_id == "c.command_injection" {
        20
    } else if rule_id == "c.format_string" {
        12
    } else if rule_id.starts_with("c.buffer_overflow") {
        8
    } else {
        0
    }
}

fn mitigation_points(f: &Finding) -> i32 {
    // Reduce score for clearly bounded/safe-but-discouraged cases.
    let msg = f.message.to_ascii_lowercase();
    let mut pts = 0;
    if msg.contains("bounded") {
        pts += 10;
    }
    if msg.contains("computed max output exceeds") {
        // Not a mitigation.
        pts -= 0;
    }
    pts
}

fn exploitability_level(f: &Finding, proven_taint: bool, implicit_risk: bool, total: u8) -> Exploitability {
    // High: confirmed attacker-control in a dangerous sink.
    if f.rule_id == "c.command_injection" && proven_taint {
        return Exploitability::High;
    }
    if f.rule_id.starts_with("c.buffer_overflow") && proven_taint {
        return Exploitability::High;
    }
    if f.rule_id == "c.format_string" && proven_taint {
        return Exploitability::High;
    }

    // Medium: implicitly exploitable patterns (e.g., pointer arithmetic) without proven taint.
    if implicit_risk && !proven_taint {
        return Exploitability::Medium;
    }

    // Low: explicitly bounded/safe patterns.
    let msg = f.message.to_ascii_lowercase();
    if msg.contains("bounded") {
        return Exploitability::Low;
    }

    // Fallback on score bands for other cases.
    if total >= 80 {
        Exploitability::High
    } else if total >= 60 {
        Exploitability::Medium
    } else {
        Exploitability::Low
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sast_core::{Finding, Location, Severity};

    fn f(rule_id: &str, severity: Severity, message: &str) -> Finding {
        Finding {
            rule_id: rule_id.to_string(),
            message: message.to_string(),
            severity,
            rank: 0,
            reason: None,
            location: Location {
                path: "a.c".to_string(),
                line: 1,
                column: 1,
            },
            snippet: None,
            conditional: false,
            guarded: false,
            tainted: false,
            implicit_risk: false,
            vuln_context: None,
            poc: None,
            source_location: None,
            path: None,
            validated: false,
            confidence: None,
            validated_path: None,
            validation_notes: None,
            exploitability_score: None,
            exploitability_level: None,
            exploit_chain: None,
        }
    }

    #[test]
    fn critical_command_injection_is_high_exploitability_and_tainted() {
        let mut fi = f(
            "c.command_injection",
            Severity::Critical,
            "Potential command injection via system with tainted data",
        );
        fi.tainted = true;
        let s = score(&[fi]);
        assert!(s.score >= 90);
        assert!(s.tainted);
        assert_eq!(s.exploitability, Exploitability::High);
    }

    #[test]
    fn low_bounded_is_low_risk() {
        let s = score(&[f(
            "c.buffer_overflow",
            Severity::Low,
            "Use of inherently dangerous function sprintf with constant bounded format",
        )]);
        assert!(s.score < 50);
        assert_eq!(s.exploitability, Exploitability::Low);
    }

    #[test]
    fn pointer_arithmetic_is_implicitly_risky_and_medium_exploitability() {
        let mut fi = f(
            "c.buffer_overflow.pointer_arithmetic",
            Severity::High,
            "Use of inherently dangerous function sprintf with pointer arithmetic destination",
        );
        fi.implicit_risk = true;
        let s = score(&[fi]);
        assert!(s.tainted, "implicit risk should set tainted=true in RBOM");
        assert_eq!(s.exploitability, Exploitability::Medium);
    }
}
