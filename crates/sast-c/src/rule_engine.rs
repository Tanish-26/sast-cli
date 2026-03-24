use sast_core::{Finding, Location, Severity};
use tree_sitter::Node;

use crate::taint::{AnalysisCtx, Scope};

pub(crate) trait Rule {
    fn id(&self) -> &'static str;
    fn check(&self, node: Node, ctx: &AnalysisCtx, scope: &Scope) -> Option<Finding>;
}

pub(crate) struct RuleRegistry {
    rules: Vec<Box<dyn Rule + Send + Sync>>,
}

impl RuleRegistry {
    pub(crate) fn new(rules: Vec<Box<dyn Rule + Send + Sync>>) -> Self {
        Self { rules }
    }

    pub(crate) fn default_c() -> Self {
        Self::new(vec![
            Box::new(crate::rulesets::sprintf::SprintfRule),
            Box::new(crate::rulesets::strcpy::StrcpyRule),
            Box::new(crate::rulesets::printf::PrintfRule),
            Box::new(crate::rulesets::command::CommandExecRule),
            Box::new(crate::rulesets::memory::DoubleFreeRule),
            Box::new(crate::rulesets::memory::UseAfterFreeRule),
        ])
    }

    pub(crate) fn check_node(&self, node: Node, ctx: &AnalysisCtx, scope: &Scope) -> Vec<Finding> {
        let mut out = Vec::new();
        for r in &self.rules {
            if let Some(f) = r.check(node, ctx, scope) {
                out.push(f);
            }
        }
        out
    }
}

pub(crate) fn finding(ctx: &AnalysisCtx, node: Node, rule_id: &str, msg: &str, sev: Severity) -> Finding {
    Finding {
        rule_id: rule_id.to_string(),
        message: msg.to_string(),
        severity: sev,
        rank: 0,
        reason: None,
        location: Location {
            path: ctx.path.clone(),
            line: node.start_position().row + 1,
            column: node.start_position().column + 1,
        },
        snippet: Some(crate::taint::single_line(crate::taint::node_text(&ctx.source, node))),
        conditional: false,
        guarded: false,
        tainted: false,
        implicit_risk: false,
        vuln_context: None,
        poc: None,
        source_location: None,
        path: None,
    }
}
