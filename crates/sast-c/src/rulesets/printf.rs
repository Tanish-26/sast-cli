use sast_core::Severity;
use tree_sitter::Node;

use crate::rule_engine::{finding, Rule};
use crate::taint::{callee_name, expr_tainted, is_string_literal_node, AnalysisCtx, Scope};

pub struct PrintfRule;

impl Rule for PrintfRule {
    fn id(&self) -> &'static str {
        "c.format_string"
    }

    fn check(&self, node: Node, ctx: &AnalysisCtx, scope: &Scope) -> Option<sast_core::Finding> {
        if node.kind() != "call_expression" {
            return None;
        }
        let callee = node.child_by_field_name("function")?;
        let name = callee_name(&ctx.source, callee)?;
        if !crate::rules::is_printf_family(&name) {
            return None;
        }
        // `sprintf`/`vsprintf` are handled by the dedicated `SprintfRule` to avoid double-reporting.
        if name == "sprintf" || name == "vsprintf" {
            return None;
        }

        let fmt = node
            .child_by_field_name("arguments")
            .and_then(|a| a.named_child(0))?;
        let is_lit = is_string_literal_node(fmt);
        if is_lit {
            return None;
        }

        let tainted = expr_tainted(&ctx.source, fmt, scope, ctx);
        let sev = if tainted {
            Severity::Critical
        } else {
            Severity::Medium
        };
        let msg = if tainted {
            "Potential format string vulnerability (tainted format)"
        } else {
            "Non-literal format string passed to printf-family function"
        };
        let mut f = finding(ctx, node, self.id(), msg, sev);
        f.vuln_context = Some(sast_core::VulnContext {
            sink: Some(name.clone()),
            input_source: None,
            buffer_size: None,
            arg_positions: Some(vec![0]),
        });
        if tainted {
            f.tainted = true;
            if let Some((src_loc, steps)) =
                crate::taint::tainted_flow_path(&ctx.source, fmt, scope, ctx, &name)
            {
                f.source_location = src_loc;
                f.path = Some(steps.clone());
                if let Some(vc) = f.vuln_context.as_mut() {
                    vc.input_source = steps.first().cloned();
                }
            }
        }
        Some(f)
    }
}
