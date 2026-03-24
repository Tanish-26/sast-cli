use sast_core::Severity;
use tree_sitter::Node;

use crate::rule_engine::{finding, Rule};
use crate::taint::{base_identifier, callee_name, is_node_within, AnalysisCtx, AllocState, Scope};

pub struct DoubleFreeRule;
pub struct UseAfterFreeRule;

impl Rule for DoubleFreeRule {
    fn id(&self) -> &'static str {
        "c.double_free"
    }

    fn check(&self, node: Node, ctx: &AnalysisCtx, scope: &Scope) -> Option<sast_core::Finding> {
        if node.kind() != "call_expression" {
            return None;
        }
        let callee = node.child_by_field_name("function")?;
        let name = callee_name(&ctx.source, callee)?;
        if name != "free" {
            return None;
        }
        let arg0 = node
            .child_by_field_name("arguments")
            .and_then(|a| a.named_child(0))?;
        let id = base_identifier(&ctx.source, arg0)?;
        let info = scope.get(&id);
        if info.alloc == AllocState::Freed {
            let mut f = finding(
                ctx,
                node,
                self.id(),
                "Potential double free()",
                Severity::High,
            );
            f.implicit_risk = true;
            f.vuln_context = Some(sast_core::VulnContext {
                sink: Some("free".to_string()),
                input_source: None,
                buffer_size: None,
                arg_positions: Some(vec![0]),
            });
            if f.path.is_none() {
                f.path = Some(vec![id, "free".to_string(), "free".to_string()]);
            }
            return Some(f);
        }
        None
    }
}

impl Rule for UseAfterFreeRule {
    fn id(&self) -> &'static str {
        "c.use_after_free"
    }

    fn check(&self, node: Node, ctx: &AnalysisCtx, scope: &Scope) -> Option<sast_core::Finding> {
        if node.kind() != "identifier" {
            return None;
        }
        let name = crate::taint::node_text(&ctx.source, node);
        let info = scope.get(&name);
        if info.alloc != AllocState::Freed {
            return None;
        }
        if is_direct_assignment_target(node) || is_in_free_arg(&ctx.source, node) {
            return None;
        }
        let mut f = finding(
            ctx,
            node,
            self.id(),
            "Potential use-after-free",
            Severity::High,
        );
        f.implicit_risk = true;
        f.vuln_context = Some(sast_core::VulnContext {
            sink: Some("use_after_free".to_string()),
            input_source: None,
            buffer_size: None,
            arg_positions: None,
        });
        if f.path.is_none() {
            f.path = Some(vec![name, "free".to_string(), "use".to_string()]);
        }
        Some(f)
    }
}

fn is_direct_assignment_target(node: Node) -> bool {
    let mut cur = node;
    while let Some(p) = cur.parent() {
        if p.kind() == "assignment_expression" {
            if let Some(left) = p.child_by_field_name("left") {
                return left.kind() == "identifier"
                    && left.start_byte() == node.start_byte()
                    && left.end_byte() == node.end_byte();
            }
            return false;
        }
        cur = p;
    }
    false
}

fn is_in_free_arg(source: &str, node: Node) -> bool {
    let mut cur = node;
    while let Some(p) = cur.parent() {
        if p.kind() == "call_expression" {
            let callee = p.child_by_field_name("function");
            if let Some(callee) = callee {
                if callee_name(source, callee).as_deref() == Some("free") {
                    if let Some(args) = p.child_by_field_name("arguments") {
                        if let Some(arg0) = args.named_child(0) {
                            return is_node_within(arg0, node);
                        }
                    }
                }
            }
        }
        cur = p;
    }
    false
}
