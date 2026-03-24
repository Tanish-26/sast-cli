use sast_core::Severity;
use tree_sitter::Node;

use crate::rule_engine::{finding, Rule};
use crate::taint::{callee_name, expr_tainted, is_string_literal_node, AnalysisCtx, Scope};

pub struct CommandExecRule;

impl Rule for CommandExecRule {
    fn id(&self) -> &'static str {
        "c.command_injection"
    }

    fn check(&self, node: Node, ctx: &AnalysisCtx, scope: &Scope) -> Option<sast_core::Finding> {
        if node.kind() != "call_expression" {
            return None;
        }
        let callee = node.child_by_field_name("function")?;
        let name = callee_name(&ctx.source, callee)?;
        let is_cmd = name == "system" || name == "popen" || name.starts_with("exec");
        if !is_cmd {
            return None;
        }

        let arg0 = node
            .child_by_field_name("arguments")
            .and_then(|a| a.named_child(0));
        let tainted = arg0.is_some_and(|a| expr_tainted(&ctx.source, a, scope, ctx));

        if tainted {
            let mut f = finding(
                ctx,
                node,
                self.id(),
                &format!("Potential command injection via {name} with tainted data"),
                Severity::Critical,
            );
            f.tainted = true;
            f.vuln_context = Some(sast_core::VulnContext {
                sink: Some(name.clone()),
                input_source: None,
                buffer_size: None,
                arg_positions: Some(vec![0]),
            });
            if let Some(arg0) = arg0 {
                if let Some((src_loc, steps)) =
                    crate::taint::tainted_flow_path(&ctx.source, arg0, scope, ctx, &name)
                {
                    f.source_location = src_loc;
                    f.path = Some(steps.clone());
                    if let Some(vc) = f.vuln_context.as_mut() {
                        vc.input_source = steps.first().cloned();
                    }
                }
            }
            Some(f)
        } else {
            let sev = if arg0.is_some_and(is_string_literal_node) {
                Severity::Low
            } else {
                Severity::Medium
            };
            let mut f = finding(
                ctx,
                node,
                self.id(),
                &format!("Use of inherently dangerous function {name}"),
                sev,
            );
            f.vuln_context = Some(sast_core::VulnContext {
                sink: Some(name),
                input_source: None,
                buffer_size: None,
                arg_positions: Some(vec![0]),
            });
            Some(f)
        }
    }
}
