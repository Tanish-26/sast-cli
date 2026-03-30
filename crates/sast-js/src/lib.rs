use std::collections::HashMap;

use sast_core::{Finding, Location, Severity};
use tree_sitter::{Node, Parser, Tree};

fn language() -> tree_sitter::Language {
    tree_sitter_javascript::LANGUAGE.into()
}

pub fn parse(source: &str) -> Result<Tree, String> {
    let mut parser = Parser::new();
    parser
        .set_language(&language())
        .map_err(|e| format!("failed to set JS language: {e:?}"))?;
    Ok(parser.parse(source, None).ok_or("parse returned None")?)
}

pub fn scan_eval_taint(source: &str, path: &str) -> Result<Vec<Finding>, String> {
    let tree = parse(source)?;
    let root = tree.root_node();
    let mut findings = Vec::new();
    let mut scope = Scope::new(None);
    scan_block(source, root, path, &mut findings, &mut scope);
    Ok(findings)
}

struct Scope<'a> {
    parent: Option<&'a Scope<'a>>,
    taint: HashMap<String, bool>,
}

impl<'a> Scope<'a> {
    fn new(parent: Option<&'a Scope<'a>>) -> Self {
        Self {
            parent,
            taint: HashMap::new(),
        }
    }

    fn get(&self, name: &str) -> bool {
        if let Some(v) = self.taint.get(name) {
            return *v;
        }
        self.parent.map(|p| p.get(name)).unwrap_or(false)
    }

    fn set(&mut self, name: String, val: bool) {
        self.taint.insert(name, val);
    }
}

fn scan_block(source: &str, node: Node, path: &str, findings: &mut Vec<Finding>, scope: &mut Scope) {
    if node.kind() == "program" || node.kind() == "statement_block" {
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            scan_stmt(source, child, path, findings, scope);
        }
        return;
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        scan_stmt(source, child, path, findings, scope);
    }
}

fn scan_stmt(source: &str, node: Node, path: &str, findings: &mut Vec<Finding>, scope: &mut Scope) {
    match node.kind() {
        "function_declaration"
        | "function"
        | "function_expression"
        | "generator_function"
        | "arrow_function"
        | "method_definition" => {
            if let Some(body) = node.child_by_field_name("body") {
                let mut nested = Scope::new(Some(scope));
                scan_block(source, body, path, findings, &mut nested);
            }
            return;
        }
        "lexical_declaration" | "variable_declaration" => {
            let mut cursor = node.walk();
            for decl in node.named_children(&mut cursor) {
                if decl.kind() == "variable_declarator" {
                    handle_var_declarator(source, decl, path, findings, scope);
                }
            }
            return;
        }
        "expression_statement" => {
            if let Some(expr) = node.named_child(0) {
                scan_expr(source, expr, path, findings, scope);
            }
            return;
        }
        "assignment_expression" => {
            handle_assignment(source, node, path, findings, scope);
            return;
        }
        _ => {}
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        scan_stmt(source, child, path, findings, scope);
    }
}

fn handle_var_declarator(
    source: &str,
    node: Node,
    path: &str,
    findings: &mut Vec<Finding>,
    scope: &mut Scope,
) {
    let target = node.child_by_field_name("name");
    let value = node.child_by_field_name("value");
    if let Some(value) = value {
        scan_expr(source, value, path, findings, scope);
    }

    let value_taint = value.map(|v| expr_tainted(source, v, scope)).unwrap_or(false);
    if let Some(target) = target {
        for ident in pattern_idents(source, target) {
            scope.set(ident, value_taint);
        }
    }
}

fn handle_assignment(
    source: &str,
    node: Node,
    path: &str,
    findings: &mut Vec<Finding>,
    scope: &mut Scope,
) {
    let left = node.child_by_field_name("left");
    let right = node.child_by_field_name("right");
    if let Some(right) = right {
        scan_expr(source, right, path, findings, scope);
    }

    let (Some(left), Some(right)) = (left, right) else {
        return;
    };

    let right_taint = expr_tainted(source, right, scope);
    if left.kind() == "identifier" {
        scope.set(node_text(source, left), right_taint);
        return;
    }

    if left.kind() == "object_pattern" || left.kind() == "array_pattern" {
        for ident in pattern_idents(source, left) {
            scope.set(ident, right_taint);
        }
    }
}

fn scan_expr(source: &str, node: Node, path: &str, findings: &mut Vec<Finding>, scope: &mut Scope) {
    if node.kind() == "assignment_expression" {
        handle_assignment(source, node, path, findings, scope);
        return;
    }

    if node.kind() == "call_expression" && is_eval_call(source, node) {
        let arg = node
            .child_by_field_name("arguments")
            .and_then(|args| args.named_child(0));
        if let Some(arg) = arg {
            if expr_tainted(source, arg, scope) {
                findings.push(Finding {
                    rule_id: "js.user_input_eval".to_string(),
                    message: "user-controlled data flows into eval()".to_string(),
                    severity: Severity::High,
                    rank: 0,
                    reason: None,
                    location: Location {
                        path: path.to_string(),
                        line: node.start_position().row + 1,
                        column: node.start_position().column + 1,
                    },
                    snippet: Some(single_line(node_text(source, node))),
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
                });
            }
        }
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        match child.kind() {
            "function_declaration"
            | "function"
            | "function_expression"
            | "generator_function"
            | "arrow_function"
            | "method_definition" => {
                if let Some(body) = child.child_by_field_name("body") {
                    let mut nested = Scope::new(Some(scope));
                    scan_block(source, body, path, findings, &mut nested);
                }
            }
            _ => scan_expr(source, child, path, findings, scope),
        }
    }
}

fn is_eval_call(source: &str, node: Node) -> bool {
    let Some(callee) = node.child_by_field_name("function") else {
        return false;
    };
    if callee.kind() == "identifier" && node_text(source, callee) == "eval" {
        return true;
    }
    if callee.kind() == "member_expression" {
        if let Some(prop) = callee.child_by_field_name("property") {
            return prop.kind() == "property_identifier" && node_text(source, prop) == "eval";
        }
    }
    false
}

fn expr_tainted(source: &str, node: Node, scope: &Scope) -> bool {
    if is_source_expr(source, node) {
        return true;
    }

    match node.kind() {
        "identifier" => scope.get(&node_text(source, node)),
        "string" | "string_fragment" | "number" | "null" | "true" | "false" => false,
        "parenthesized_expression" => node.named_child(0).map(|c| expr_tainted(source, c, scope)).unwrap_or(false),
        "member_expression" | "subscript_expression" => {
            let obj = node
                .child_by_field_name("object")
                .or_else(|| node.child_by_field_name("value"));
            if obj.is_some_and(|o| expr_tainted(source, o, scope)) {
                return true;
            }
            let idx = node.child_by_field_name("index");
            if idx.is_some_and(|i| expr_tainted(source, i, scope)) {
                return true;
            }
            false
        }
        "binary_expression" | "logical_expression" | "ternary_expression" | "template_string" | "template_substitution" => {
            let mut cursor = node.walk();
            let any = node
                .named_children(&mut cursor)
                .any(|c| expr_tainted(source, c, scope));
            any
        }
        "call_expression" => {
            let args = node.child_by_field_name("arguments");
            let args_tainted = if let Some(a) = args {
                let mut cursor = a.walk();
                let any = a
                    .named_children(&mut cursor)
                    .any(|c| expr_tainted(source, c, scope));
                any
            } else {
                false
            };
            if args_tainted {
                return true;
            }
            let callee = node.child_by_field_name("function");
            if let Some(callee) = callee {
                if callee.kind() == "member_expression" || callee.kind() == "subscript_expression" {
                    let obj = callee
                        .child_by_field_name("object")
                        .or_else(|| callee.child_by_field_name("value"));
                    if obj.is_some_and(|o| expr_tainted(source, o, scope)) {
                        return true;
                    }
                }
            }
            false
        }
        _ => {
            let mut cursor = node.walk();
            let any = node
                .named_children(&mut cursor)
                .any(|c| expr_tainted(source, c, scope));
            any
        }
    }
}

fn is_source_expr(source: &str, node: Node) -> bool {
    match node.kind() {
        "call_expression" => {
            let Some(fn_node) = node.child_by_field_name("function") else {
                return false;
            };
            if fn_node.kind() == "identifier" && node_text(source, fn_node) == "prompt" {
                return true;
            }
            if fn_node.kind() == "member_expression" {
                let obj = fn_node.child_by_field_name("object");
                let prop = fn_node.child_by_field_name("property");
                if let (Some(obj), Some(prop)) = (obj, prop) {
                    let o = node_text(source, obj);
                    let p = node_text(source, prop);
                    return (o == "localStorage" || o == "sessionStorage") && p == "getItem";
                }
            }
            false
        }
        "member_expression" => {
            let obj = node.child_by_field_name("object");
            let prop = node.child_by_field_name("property");
            let (Some(obj), Some(prop)) = (obj, prop) else {
                return false;
            };

            // document.getElementById(...).value and friends.
            if prop.kind() == "property_identifier" && node_text(source, prop) == "value" {
                if obj.kind() == "call_expression" {
                    if let Some(fn_node) = obj.child_by_field_name("function") {
                        if fn_node.kind() == "member_expression" {
                            let fn_obj = fn_node.child_by_field_name("object");
                            let fn_prop = fn_node.child_by_field_name("property");
                            if let (Some(fn_obj), Some(fn_prop)) = (fn_obj, fn_prop) {
                                if fn_obj.kind() == "identifier"
                                    && node_text(source, fn_obj) == "document"
                                    && fn_prop.kind() == "property_identifier"
                                {
                                    let p = node_text(source, fn_prop);
                                    return matches!(
                                        p.as_str(),
                                        "getElementById"
                                            | "querySelector"
                                            | "querySelectorAll"
                                            | "getElementsByName"
                                            | "getElementsByClassName"
                                    );
                                }
                            }
                        }
                    }
                }
            }

            if obj.kind() == "identifier" && node_text(source, obj) == "process" {
                if prop.kind() == "property_identifier" {
                    let p = node_text(source, prop);
                    return p == "argv" || p == "env";
                }
            }
            if obj.kind() == "identifier" {
                let o = node_text(source, obj);
                if o == "req" || o == "request" {
                    if prop.kind() == "property_identifier" {
                        let p = node_text(source, prop);
                        return matches!(p.as_str(), "body" | "query" | "params" | "headers");
                    }
                }
                if o == "location" && prop.kind() == "property_identifier" {
                    let p = node_text(source, prop);
                    return p == "search" || p == "hash" || p == "href";
                }
                if o == "document" && prop.kind() == "property_identifier" {
                    let p = node_text(source, prop);
                    return matches!(p.as_str(), "URL" | "location" | "documentURI" | "referrer");
                }
                if o == "window" && prop.kind() == "property_identifier" && node_text(source, prop) == "name" {
                    return true;
                }
            }
            false
        }
        "subscript_expression" => {
            let obj = node
                .child_by_field_name("object")
                .or_else(|| node.child_by_field_name("value"));
            obj.is_some_and(|o| o.kind() == "member_expression" && is_source_expr(source, o))
        }
        _ => false,
    }
}

fn pattern_idents(source: &str, node: Node) -> Vec<String> {
    let mut out = Vec::new();
    match node.kind() {
        "identifier" | "shorthand_property_identifier_pattern" => out.push(node_text(source, node)),
        _ => {
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                out.extend(pattern_idents(source, child));
            }
        }
    }
    out
}

fn node_text(source: &str, node: Node) -> String {
    source
        .get(node.byte_range())
        .unwrap_or("")
        .to_string()
}

fn single_line(s: String) -> String {
    let collapsed = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.len() > 180 {
        format!("{}…", &collapsed[..179])
    } else {
        collapsed
    }
}
