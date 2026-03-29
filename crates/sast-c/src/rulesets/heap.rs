use sast_core::Severity;
use tree_sitter::Node;

use crate::rule_engine::{finding, Rule};
use crate::taint::{base_identifier, expr_range, node_text, resolved_callee_name, AnalysisCtx, AllocState, Scope};

pub struct HeapIndexRule;
pub struct MemcpyMemsetRule;

impl Rule for HeapIndexRule {
    fn id(&self) -> &'static str {
        "c.buffer_overflow"
    }

    fn check(&self, node: Node, ctx: &AnalysisCtx, scope: &Scope) -> Option<sast_core::Finding> {
        if node.kind() != "subscript_expression" {
            return None;
        }
        let arg = node
            .child_by_field_name("argument")
            .or_else(|| node.child_by_field_name("left"))
            .or_else(|| node.named_child(0))?;
        let idx = node
            .child_by_field_name("index")
            .or_else(|| node.child_by_field_name("right"))
            .or_else(|| node.named_child(1))?;

        let base = base_identifier(&ctx.source, arg)?;
        let info = scope.get(&base);
        let Some(mid) = info.mem_id else {
            return None;
        };
        let Some(mem) = scope.mem_get(mid) else {
            return None;
        };
        if mem.state == AllocState::Freed {
            // Let UAF rule handle this; avoid double-reporting.
            return None;
        }
        let Some(size) = mem.size else {
            return None;
        };
        let r = expr_range(&ctx.source, idx, scope)?;
        if r.max < 0 {
            return None;
        }

        let max = r.max as i64;
        let size_i = size as i64;
        if max < size_i {
            return None;
        }

        let (msg, sev) = if max == size_i {
            (
                "Potential off-by-one heap buffer overflow (index may equal allocation size)",
                Severity::High,
            )
        } else {
            (
                "Potential heap buffer overflow (index may exceed allocation size)",
                Severity::High,
            )
        };

        let mut f = finding(ctx, node, self.id(), msg, sev);
        f.implicit_risk = true;
        // Lightweight flow: `p -> p[i] -> heap_index`.
        let idx_txt = node_text(&ctx.source, idx);
        f.path = Some(vec![base.clone(), format!("{base}[{idx_txt}]"), "heap_index".to_string()]);
        f.vuln_context = Some(sast_core::VulnContext {
            sink: Some("heap_index".to_string()),
            input_source: None,
            buffer_size: Some(size),
            arg_positions: None,
        });
        Some(f)
    }
}

impl Rule for MemcpyMemsetRule {
    fn id(&self) -> &'static str {
        "c.buffer_overflow"
    }

    fn check(&self, node: Node, ctx: &AnalysisCtx, scope: &Scope) -> Option<sast_core::Finding> {
        if node.kind() != "call_expression" {
            return None;
        }
        let callee = node.child_by_field_name("function")?;
        let name = resolved_callee_name(&ctx.source, callee, scope)?;
        if name != "memcpy" && name != "memset" {
            return None;
        }
        let args = node.child_by_field_name("arguments")?;
        let dst = args.named_child(0)?;
        let n = if name == "memcpy" {
            args.named_child(2)?
        } else {
            args.named_child(2)?
        };

        let base = base_identifier(&ctx.source, dst)?;
        let info = scope.get(&base);
        let Some(mid) = info.mem_id else {
            return None;
        };
        let Some(mem) = scope.mem_get(mid) else {
            return None;
        };
        let Some(size) = mem.size else {
            return None;
        };

        let n_txt = node_text(&ctx.source, n);
        let Some(n_const) = parse_usize(&n_txt) else {
            return None;
        };
        if n_const <= size {
            return None;
        }

        let mut f = finding(
            ctx,
            node,
            self.id(),
            &format!("Potential heap overflow: {name} size argument exceeds allocation size"),
            Severity::High,
        );
        f.implicit_risk = true;
        f.vuln_context = Some(sast_core::VulnContext {
            sink: Some(name),
            input_source: None,
            buffer_size: Some(size),
            arg_positions: Some(vec![2]),
        });
        Some(f)
    }
}

fn parse_usize(s: &str) -> Option<usize> {
    let t = s.trim();
    if t.is_empty() {
        return None;
    }
    if t.starts_with("0x") || t.starts_with("0X") {
        usize::from_str_radix(t.trim_start_matches("0x").trim_start_matches("0X"), 16).ok()
    } else {
        t.parse::<usize>().ok()
    }
}
