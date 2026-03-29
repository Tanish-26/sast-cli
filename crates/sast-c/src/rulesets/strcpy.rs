use sast_core::Severity;
use tree_sitter::Node;

use crate::rule_engine::{finding, Rule};
use crate::taint::{
    dst_has_pointer_arithmetic, expr_tainted, is_const_copy_safe, resolved_callee_name, AnalysisCtx, Scope,
};

pub struct StrcpyRule;

impl Rule for StrcpyRule {
    fn id(&self) -> &'static str {
        "c.buffer_overflow"
    }

    fn check(&self, node: Node, ctx: &AnalysisCtx, scope: &Scope) -> Option<sast_core::Finding> {
        if node.kind() != "call_expression" {
            return None;
        }
        let callee = node.child_by_field_name("function")?;
        let name = resolved_callee_name(&ctx.source, callee, scope)?;
        let is_target = matches!(name.as_str(), "strcpy" | "strcat" | "gets");
        if !is_target {
            return None;
        }

        let args = node.child_by_field_name("arguments");
        let dst = args.as_ref().and_then(|a| a.named_child(0));
        let src = args.as_ref().and_then(|a| a.named_child(1));
        let is_ptr_arith = dst.is_some_and(dst_has_pointer_arithmetic);

        // gets() is always unbounded.
        let is_tainted = if name == "gets" {
            true
        } else {
            src.is_some_and(|s| expr_tainted(&ctx.source, s, scope, ctx))
        };

        if !is_tainted && name == "strcpy" {
            if let (Some(d), Some(s)) = (dst, src) {
                if is_const_copy_safe(&ctx.source, d, s, scope) {
                    return None;
                }
            }
        }

        let (rule_id, sev, msg) = if is_ptr_arith {
            (
                "c.buffer_overflow.pointer_arithmetic",
                if is_tainted { Severity::Critical } else { Severity::High },
                format!("Potential buffer overflow via {name} with pointer arithmetic destination"),
            )
        } else if is_tainted {
            (
                "c.buffer_overflow",
                Severity::Critical,
                format!("Potential buffer overflow via {name} with tainted data"),
            )
        } else {
            (
                "c.buffer_overflow",
                Severity::Medium,
                format!("Use of inherently dangerous function {name}"),
            )
        };

        let mut f = finding(ctx, node, rule_id, &msg, sev);
        let buf_size = dst
            .and_then(|d| crate::taint::base_identifier(&ctx.source, d))
            .and_then(|id| scope.get(&id).buf_len);
        f.vuln_context = Some(sast_core::VulnContext {
            sink: Some(name.clone()),
            input_source: None,
            buffer_size: buf_size,
            arg_positions: Some(if name == "gets" { vec![0] } else { vec![0, 1] }),
        });
        if is_tainted {
            f.tainted = true;
            // `gets(dst)` is inherently user-controlled; prefer showing dst var if available.
            let flow_expr = if name == "gets" {
                dst
            } else {
                src
            };
            if let Some(flow_expr) = flow_expr {
                if let Some((src_loc, steps)) =
                    crate::taint::tainted_flow_path(&ctx.source, flow_expr, scope, ctx, &name)
                {
                    f.source_location = src_loc;
                    // Enrich taint path with destination variable flow so exploit-chain detection can link via shared vars.
                    let mut enriched = steps.clone();
                    if let Some(d) = dst {
                        let dst_txt = crate::taint::node_text(&ctx.source, d);
                        let base = crate::taint::base_identifier(&ctx.source, d).unwrap_or(dst_txt.clone());
                        if enriched.last().is_some_and(|s| s == &name) {
                            enriched.pop();
                            enriched.push(base.clone());
                            if dst_txt != base {
                                enriched.push(dst_txt);
                            }
                            enriched.push(name.clone());
                        } else {
                            enriched.push(base);
                            enriched.push(name.clone());
                        }
                    }
                    f.path = Some(enriched);
                    if let Some(vc) = f.vuln_context.as_mut() {
                        vc.input_source = steps.first().cloned();
                    }
                }
            }
        }
        if is_ptr_arith {
            f.implicit_risk = true;
            if f.path.is_none() {
                if let Some(d) = dst {
                    let dst_txt = crate::taint::node_text(&ctx.source, d);
                    let base =
                        crate::taint::base_identifier(&ctx.source, d).unwrap_or(dst_txt.clone());
                    let mut steps = vec![base];
                    if dst_txt != steps[0] {
                        steps.push(dst_txt);
                    }
                    steps.push(name.clone());
                    f.path = Some(steps);
                }
            }
        }
        if rule_id == "c.buffer_overflow" && sev == Severity::High {
            f.implicit_risk = true;
        }

        let dst_id = dst.and_then(|d| crate::taint::base_identifier(&ctx.source, d));
        if let Some(gs) =
            crate::taint::guard_strength_for_node(&ctx.source, node, dst_id.as_deref(), scope, ctx)
        {
            let before = f.severity;
            f.guarded = true;
            f.severity = match (f.severity, gs) {
                (Severity::High, _) => Severity::Medium,
                (Severity::Medium, crate::taint::GuardStrength::Strong) => Severity::Low,
                (sev, _) => sev,
            };
            if f.severity != before {
                f.reason = Some("guard present".to_string());
            }
        }
        Some(f)
    }
}
