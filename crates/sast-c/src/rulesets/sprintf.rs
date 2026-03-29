use sast_core::Severity;
use tree_sitter::Node;

use crate::rule_engine::{finding, Rule};
use crate::taint::{
    dst_has_pointer_arithmetic, expr_tainted, is_string_literal_node, resolved_callee_name,
    sprintf_format_is_bounded, sprintf_max_len, AnalysisCtx, Scope,
};

pub struct SprintfRule;

impl Rule for SprintfRule {
    fn id(&self) -> &'static str {
        "c.buffer_overflow"
    }

    fn check(&self, node: Node, ctx: &AnalysisCtx, scope: &Scope) -> Option<sast_core::Finding> {
        if node.kind() != "call_expression" {
            return None;
        }
        let callee = node.child_by_field_name("function")?;
        let name = resolved_callee_name(&ctx.source, callee, scope)?;
        if name != "sprintf" && name != "vsprintf" {
            return None;
        }

        let args = node.child_by_field_name("arguments")?;
        let dst = args.named_child(0)?;
        let fmt = args.named_child(1)?;
        let buf_size = crate::taint::base_identifier(&ctx.source, dst).and_then(|id| scope.get(&id).buf_len);
        let guard_strength = crate::taint::guard_strength_for_node(
            &ctx.source,
            node,
            crate::taint::base_identifier(&ctx.source, dst).as_deref(),
            scope,
            ctx,
        );

        let fmt_is_lit = is_string_literal_node(fmt);
        let fmt_tainted = expr_tainted(&ctx.source, fmt, scope, ctx);
        if fmt_tainted && !fmt_is_lit {
            let mut f = finding(
                ctx,
                node,
                "c.format_string",
                "Potential format string vulnerability via sprintf (tainted format string)",
                Severity::Critical,
            );
            f.tainted = true;
            f.implicit_risk = true;
            f.vuln_context = Some(sast_core::VulnContext {
                sink: Some(name.clone()),
                input_source: None,
                buffer_size: buf_size,
                arg_positions: Some(vec![1]),
            });
            if let Some((src_loc, steps)) =
                crate::taint::tainted_flow_path(&ctx.source, fmt, scope, ctx, &name)
            {
                f.source_location = src_loc;
                f.path = Some(steps.clone());
                if let Some(vc) = f.vuln_context.as_mut() {
                    vc.input_source = steps.first().cloned();
                }
            }
            return Some(f);
        }

        let tainted_any = has_tainted_args(&ctx.source, args, scope, ctx);
        let ptr_arith = dst_has_pointer_arithmetic(dst);
        if ptr_arith {
            let sev = if tainted_any { Severity::Critical } else { Severity::High };
            let mut f = finding(
                ctx,
                node,
                "c.buffer_overflow.pointer_arithmetic",
                "Use of inherently dangerous function sprintf with pointer arithmetic destination",
                sev,
            );
            f.implicit_risk = true;
            f.vuln_context = Some(sast_core::VulnContext {
                sink: Some(name.clone()),
                input_source: None,
                buffer_size: buf_size,
                arg_positions: Some(vec![0]),
            });
            // Add a lightweight flow path even without proven taint: `buf -> buf+sz -> sprintf`.
            if f.path.is_none() {
                let dst_txt = crate::taint::node_text(&ctx.source, dst);
                let base = crate::taint::base_identifier(&ctx.source, dst).unwrap_or(dst_txt.clone());
                let mut steps = vec![base];
                if dst_txt != steps[0] {
                    steps.push(dst_txt);
                }
                steps.push(name.clone());
                f.path = Some(steps);
            }
            if tainted_any {
                f.tainted = true;
                if let Some(idx) = first_tainted_arg_index(&ctx.source, args, scope, ctx) {
                    if let Some(arg) = args.named_child(idx) {
                        if let Some((src_loc, steps)) =
                            crate::taint::tainted_flow_path(&ctx.source, arg, scope, ctx, &name)
                        {
                            f.source_location = src_loc;
                            // Enrich taint path with destination variable flow for exploit-chain linking.
                            let mut enriched = steps.clone();
                            let dst_txt = crate::taint::node_text(&ctx.source, dst);
                            let base =
                                crate::taint::base_identifier(&ctx.source, dst).unwrap_or(dst_txt.clone());
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
                            f.path = Some(enriched);
                            if let Some(vc) = f.vuln_context.as_mut() {
                                vc.input_source = steps.first().cloned();
                                // also record which argument carried the taint
                                let mut ap = vc.arg_positions.clone().unwrap_or_default();
                                if !ap.contains(&idx) {
                                    ap.push(idx);
                                    ap.sort_unstable();
                                    vc.arg_positions = Some(ap);
                                }
                            }
                        }
                    }
                }
            }
            if let Some(gs) = guard_strength {
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
            return Some(f);
        }

        if tainted_any {
            let mut f = finding(
                ctx,
                node,
                "c.buffer_overflow",
                "Potential buffer overflow via sprintf with tainted data",
                Severity::Critical,
            );
            f.tainted = true;
            f.implicit_risk = true;
            f.vuln_context = Some(sast_core::VulnContext {
                sink: Some(name.clone()),
                input_source: None,
                buffer_size: buf_size,
                arg_positions: Some(vec![0]),
            });
            if let Some(idx) = first_tainted_arg_index(&ctx.source, args, scope, ctx) {
                if let Some(arg) = args.named_child(idx) {
                    if let Some((src_loc, steps)) =
                        crate::taint::tainted_flow_path(&ctx.source, arg, scope, ctx, &name)
                    {
                        f.source_location = src_loc;
                        // Enrich taint path with destination variable flow for exploit-chain linking.
                        let mut enriched = steps.clone();
                        let dst_txt = crate::taint::node_text(&ctx.source, dst);
                        let base =
                            crate::taint::base_identifier(&ctx.source, dst).unwrap_or(dst_txt.clone());
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
                        f.path = Some(enriched);
                        if let Some(vc) = f.vuln_context.as_mut() {
                            vc.input_source = steps.first().cloned();
                            let mut ap = vc.arg_positions.clone().unwrap_or_default();
                            if !ap.contains(&idx) {
                                ap.push(idx);
                                ap.sort_unstable();
                                vc.arg_positions = Some(ap);
                            }
                        }
                    }
                }
            }
            return Some(f);
        }

        if fmt_is_lit {
            // If we can bound length and have a known dest capacity, suppress/raise overflow.
            let cap = buf_size;
            if let Some(max_len) = sprintf_max_len(&ctx.source, fmt, &args) {
                if let Some(cap) = cap {
                    if (max_len + 1) <= cap {
                        return None;
                    }
                    let mut f = finding(
                        ctx,
                        node,
                        "c.buffer_overflow",
                        "Potential buffer overflow via sprintf (computed max output exceeds destination)",
                        Severity::High,
                    );
                    f.implicit_risk = true;
                    f.vuln_context = Some(sast_core::VulnContext {
                        sink: Some(name.clone()),
                        input_source: None,
                        buffer_size: buf_size,
                        arg_positions: Some(vec![0]),
                    });
                    if let Some(gs) = guard_strength {
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
                    return Some(f);
                }
            }

            if sprintf_format_is_bounded(&ctx.source, fmt) {
                let mut f = finding(
                    ctx,
                    node,
                    "c.buffer_overflow",
                    "Use of inherently dangerous function sprintf with constant bounded format",
                    Severity::Low,
                );
                f.reason = Some("bounded write".to_string());
                f.vuln_context = Some(sast_core::VulnContext {
                    sink: Some(name.clone()),
                    input_source: None,
                    buffer_size: buf_size,
                    arg_positions: Some(vec![0, 1]),
                });
                return Some(f);
            }

            // If it's a constant without placeholders and we can prove it fits, suppress. Otherwise keep medium.
            if args.named_child_count() == 2 {
                if let Some(cap) = cap {
                    if let Some(n) = crate::taint::string_literal_len(&ctx.source, fmt) {
                        let raw = crate::taint::node_text(&ctx.source, fmt);
                        let no_esc = raw.replace("%%", "");
                        if !no_esc.contains('%') && (n + 1) <= cap {
                            return None;
                        }
                    }
                }
            }
        }

        let mut f = finding(
            ctx,
            node,
            "c.buffer_overflow",
            &format!("Use of inherently dangerous function {name}"),
            Severity::Medium,
        );
        f.vuln_context = Some(sast_core::VulnContext {
            sink: Some(name),
            input_source: None,
            buffer_size: buf_size,
            arg_positions: Some(vec![0, 1]),
        });
        if let Some(gs) = guard_strength {
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

fn has_tainted_args(source: &str, args: Node, scope: &Scope, ctx: &AnalysisCtx) -> bool {
    let mut cursor = args.walk();
    for (idx, arg) in args.named_children(&mut cursor).enumerate() {
        if idx == 0 {
            continue;
        }
        if expr_tainted(source, arg, scope, ctx) {
            return true;
        }
    }
    false
}

fn first_tainted_arg_index(source: &str, args: Node, scope: &Scope, ctx: &AnalysisCtx) -> Option<usize> {
    let mut cursor = args.walk();
    for (idx, arg) in args.named_children(&mut cursor).enumerate() {
        if idx == 0 {
            continue;
        }
        if expr_tainted(source, arg, scope, ctx) {
            return Some(idx);
        }
    }
    None
}
