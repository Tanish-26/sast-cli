use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};

use sast_core::{Finding, Location};
use tree_sitter::{Node, Tree};

use crate::parser::{self, CFamilyLanguage};
use crate::rules::{self, SinkKind, SourceKind};

#[derive(Debug, Clone, PartialEq, Eq)]
enum ReturnTaint {
    Never,
    Always,
    FromParams(BTreeSet<usize>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FnSummary {
    ret: ReturnTaint,
}

#[derive(Debug, Default)]
pub(crate) struct AnalysisCtx {
    summaries: BTreeMap<String, FnSummary>,
    #[allow(dead_code)]
    cfgs: BTreeMap<String, crate::cfg::Cfg>,
    pub(crate) source: String,
    pub(crate) path: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AllocState {
    Unknown,
    Allocated,
    Freed,
}

#[derive(Debug, Clone)]
pub(crate) struct VarInfo {
    pub(crate) tainted: bool,
    pub(crate) alloc: AllocState,
    pub(crate) buf_len: Option<usize>,
    pub(crate) mem_id: Option<u64>,
    pub(crate) range: Option<IntRange>,
    pub(crate) taint_meta: Option<TaintMeta>,
}

impl Default for VarInfo {
    fn default() -> Self {
        Self {
            tainted: false,
            alloc: AllocState::Unknown,
            buf_len: None,
            mem_id: None,
            range: None,
            taint_meta: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct IntRange {
    pub(crate) min: i64,
    pub(crate) max: i64,
}

#[derive(Debug, Clone)]
pub(crate) struct MemInfo {
    pub(crate) state: AllocState,
    pub(crate) size: Option<usize>,
}

pub(crate) struct Scope<'a> {
    parent: Option<&'a Scope<'a>>,
    vars: HashMap<String, VarInfo>,
    alias_adj: HashMap<String, BTreeSet<String>>,
    mem: HashMap<u64, MemInfo>,
    fn_alias: HashMap<String, String>,
    fn_ptr: BTreeSet<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct TaintSource {
    pub(crate) kind: String,
    pub(crate) location: Location,
}

#[derive(Debug, Clone)]
pub(crate) struct TaintMeta {
    pub(crate) source: Option<TaintSource>,
    pub(crate) prev: Option<String>,
}

impl<'a> Scope<'a> {
    fn new(parent: Option<&'a Scope<'a>>) -> Self {
        Self {
            parent,
            vars: HashMap::new(),
            alias_adj: HashMap::new(),
            mem: HashMap::new(),
            fn_alias: HashMap::new(),
            fn_ptr: BTreeSet::new(),
        }
    }

    pub(crate) fn get(&self, name: &str) -> VarInfo {
        if let Some(v) = self.vars.get(name) {
            return v.clone();
        }
        self.parent.map(|p| p.get(name)).unwrap_or_default()
    }

    pub(crate) fn set(&mut self, name: String, info: VarInfo) {
        self.vars.insert(name, info);
    }

    pub(crate) fn set_range(&mut self, name: &str, range: Option<IntRange>) {
        let mut info = self.get(name);
        info.range = range;
        self.set(name.to_string(), info);
    }

    pub(crate) fn mem_get(&self, id: u64) -> Option<MemInfo> {
        if let Some(m) = self.mem.get(&id) {
            return Some(m.clone());
        }
        self.parent.and_then(|p| p.mem_get(id))
    }

    pub(crate) fn mem_set(&mut self, id: u64, info: MemInfo) {
        self.mem.insert(id, info);
    }

    pub(crate) fn set_fn_alias(&mut self, name: &str, target: &str) {
        if name.is_empty() || target.is_empty() {
            return;
        }
        self.fn_alias.insert(name.to_string(), target.to_string());
    }

    pub(crate) fn resolve_fn_alias(&self, name: &str) -> Option<String> {
        let mut cur = name.to_string();
        for _ in 0..16 {
            let next = self
                .fn_alias
                .get(&cur)
                .cloned()
                .or_else(|| self.parent.and_then(|p| p.fn_alias.get(&cur).cloned()));
            let Some(next) = next else { break };
            if next == cur {
                break;
            }
            cur = next;
        }
        if cur == name { None } else { Some(cur) }
    }

    pub(crate) fn add_alias(&mut self, a: &str, b: &str) {
        if a.is_empty() || b.is_empty() || a == b {
            return;
        }
        self.alias_adj
            .entry(a.to_string())
            .or_default()
            .insert(b.to_string());
        self.alias_adj
            .entry(b.to_string())
            .or_default()
            .insert(a.to_string());

        // Best-effort: share known fixed buffer sizes across aliases.
        let a_info = self.get(a);
        let b_info = self.get(b);
        match (a_info.buf_len, b_info.buf_len) {
            (Some(n), None) => {
                let mut updated = b_info.clone();
                updated.buf_len = Some(n);
                self.set(b.to_string(), updated);
            }
            (None, Some(n)) => {
                let mut updated = a_info.clone();
                updated.buf_len = Some(n);
                self.set(a.to_string(), updated);
            }
            _ => {}
        }
    }

    pub(crate) fn taint_var(&mut self, name: &str, meta: TaintMeta) {
        let mut seen = BTreeSet::new();
        let mut q: VecDeque<(String, Option<String>)> = VecDeque::new();
        q.push_back((name.to_string(), None));

        while let Some((cur, parent)) = q.pop_front() {
            if !seen.insert(cur.clone()) {
                continue;
            }

            let mut info = self.get(&cur);
            info.tainted = true;
            if info.taint_meta.is_none() {
                info.taint_meta = Some(if let Some(p) = parent.clone() {
                    TaintMeta {
                        source: meta.source.clone(),
                        prev: Some(p),
                    }
                } else {
                    meta.clone()
                });
            }
            self.set(cur.clone(), info);

            if let Some(nbrs) = self.alias_adj.get(&cur) {
                for n in nbrs {
                    if !seen.contains(n) {
                        q.push_back((n.clone(), Some(cur.clone())));
                    }
                }
            }
        }
    }

    pub(crate) fn taint_chain(&self, leaf: &str) -> (Option<Location>, Vec<String>) {
        let mut chain_vars: Vec<String> = Vec::new();
        let mut cur = leaf.to_string();
        let mut source_loc: Option<Location> = None;
        let mut source_kind: Option<String> = None;
        for _ in 0..32 {
            chain_vars.push(cur.clone());
            let info = self.get(&cur);
            let Some(meta) = info.taint_meta else { break };
            if source_kind.is_none() {
                if let Some(src) = &meta.source {
                    source_kind = Some(src.kind.clone());
                    source_loc = Some(src.location.clone());
                }
            }
            let Some(prev) = meta.prev.clone() else { break };
            cur = prev;
        }
        chain_vars.reverse();
        let mut steps: Vec<String> = Vec::new();
        if let Some(k) = source_kind {
            steps.push(k);
        }
        steps.extend(chain_vars);
        (source_loc, steps)
    }

    pub(crate) fn mark_fn_ptr(&mut self, name: &str) {
        if !name.is_empty() {
            self.fn_ptr.insert(name.to_string());
        }
    }

    pub(crate) fn is_fn_ptr(&self, name: &str) -> bool {
        if self.fn_ptr.contains(name) {
            return true;
        }
        self.parent.map(|p| p.is_fn_ptr(name)).unwrap_or(false)
    }
}

pub fn scan_c_family(source: &str, path: &str, language: CFamilyLanguage) -> Result<Vec<Finding>, String> {
    let tree = parser::parse(source, language)?;
    let ctx = build_ctx(source, path, &tree);
    Ok(scan_tree(source, path, &tree, &ctx))
}

fn build_ctx(source: &str, path: &str, tree: &Tree) -> AnalysisCtx {
    let root = tree.root_node();
    let funcs = collect_function_defs(source, root);
    let mut summaries: BTreeMap<String, FnSummary> = BTreeMap::new();
    for (name, _) in &funcs {
        summaries.insert(name.clone(), FnSummary { ret: ReturnTaint::Never });
    }

    // Iteratively refine summaries to handle simple call chains (no recursion required).
    for _ in 0..8 {
        let mut changed = false;
        for (name, node) in &funcs {
            let new_sum = summarize_function(source, *node, &summaries);
            if summaries.get(name) != Some(&new_sum) {
                summaries.insert(name.clone(), new_sum);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }

    let mut cfgs = BTreeMap::new();
    for (name, node) in &funcs {
        if let Some(body) = node.child_by_field_name("body") {
            cfgs.insert(name.clone(), crate::cfg::build_cfg_for_function(body));
        }
    }

    AnalysisCtx {
        summaries,
        cfgs,
        source: source.to_string(),
        path: path.to_string(),
    }
}

fn collect_function_defs<'a>(source: &str, root: Node<'a>) -> Vec<(String, Node<'a>)> {
    let mut out = Vec::new();
    collect_function_defs_rec(source, root, &mut out);
    out
}

fn collect_function_defs_rec<'a>(source: &str, node: Node<'a>, out: &mut Vec<(String, Node<'a>)>) {
    if node.kind() == "function_definition" {
        if let Some(name) = function_name_from_def(source, node) {
            out.push((name, node));
        }
        return;
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_function_defs_rec(source, child, out);
    }
}

fn function_name_from_def(source: &str, def: Node) -> Option<String> {
    let decl = def.child_by_field_name("declarator")?;
    find_first_identifier(source, decl)
}

fn function_params_from_def(source: &str, def: Node) -> Vec<String> {
    let mut out = Vec::new();
    let Some(decl) = def.child_by_field_name("declarator") else {
        return out;
    };
    let param_list = find_first_kind(decl, "parameter_list");
    let Some(param_list) = param_list else {
        return out;
    };

    let mut cursor = param_list.walk();
    for param in param_list.named_children(&mut cursor) {
        if param.kind() == "parameter_declaration" {
            if let Some(name) = find_first_identifier(source, param) {
                out.push(name);
            }
        }
    }
    out
}

fn summarize_function(source: &str, def: Node<'_>, summaries: &BTreeMap<String, FnSummary>) -> FnSummary {
    let params = function_params_from_def(source, def);
    let mut env = SummaryEnv::new(&params, summaries);
    let mut ret = TaintExpr::Never;

    let Some(body) = def.child_by_field_name("body") else {
        return FnSummary { ret: ReturnTaint::Never };
    };
    summarize_block(source, body, &mut env, &mut ret);

    let ret = match ret {
        TaintExpr::Always => ReturnTaint::Always,
        TaintExpr::Depends(s) if !s.is_empty() => ReturnTaint::FromParams(s),
        _ => ReturnTaint::Never,
    };
    FnSummary { ret }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TaintExpr {
    Never,
    Always,
    Depends(BTreeSet<usize>),
}

impl TaintExpr {
    fn join(self, other: TaintExpr) -> TaintExpr {
        match (self, other) {
            (TaintExpr::Always, _) | (_, TaintExpr::Always) => TaintExpr::Always,
            (TaintExpr::Depends(a), TaintExpr::Depends(b)) => {
                let mut out = a;
                out.extend(b);
                TaintExpr::Depends(out)
            }
            (TaintExpr::Depends(a), TaintExpr::Never) | (TaintExpr::Never, TaintExpr::Depends(a)) => {
                TaintExpr::Depends(a)
            }
            (TaintExpr::Never, TaintExpr::Never) => TaintExpr::Never,
        }
    }
}

struct SummaryEnv<'a> {
    vars: HashMap<String, TaintExpr>,
    summaries: &'a BTreeMap<String, FnSummary>,
}

impl<'a> SummaryEnv<'a> {
    fn new(params: &'a [String], summaries: &'a BTreeMap<String, FnSummary>) -> Self {
        let mut vars = HashMap::new();
        for (idx, p) in params.iter().enumerate() {
            vars.insert(p.clone(), TaintExpr::Depends(BTreeSet::from([idx])));
        }
        Self {
            vars,
            summaries,
        }
    }

    fn get(&self, name: &str) -> TaintExpr {
        self.vars.get(name).cloned().unwrap_or(TaintExpr::Never)
    }

    fn set(&mut self, name: String, val: TaintExpr) {
        self.vars.insert(name, val);
    }
}

fn summarize_block(source: &str, node: Node<'_>, env: &mut SummaryEnv<'_>, ret: &mut TaintExpr) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        summarize_stmt(source, child, env, ret);
    }
}

fn summarize_stmt(source: &str, node: Node<'_>, env: &mut SummaryEnv<'_>, ret: &mut TaintExpr) {
    match node.kind() {
        "compound_statement" => {
            summarize_block(source, node, env, ret);
            return;
        }
        "declaration" => {
            summarize_decl(source, node, env);
            return;
        }
        "expression_statement" => {
            if let Some(expr) = node.named_child(0) {
                summarize_expr(source, expr, env);
            }
            return;
        }
        "return_statement" => {
            if let Some(expr) = node
                .child_by_field_name("argument")
                .or_else(|| node.child_by_field_name("value"))
                .or_else(|| node.named_child(0))
            {
                *ret = ret.clone().join(summarize_expr(source, expr, env));
            }
            return;
        }
        _ => {}
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        summarize_stmt(source, child, env, ret);
    }
}

fn summarize_decl(source: &str, node: Node<'_>, env: &mut SummaryEnv<'_>) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() == "init_declarator" {
            let declarator = child.child_by_field_name("declarator");
            let value = child.child_by_field_name("value");
            let val = value.map(|v| summarize_expr(source, v, env)).unwrap_or(TaintExpr::Never);
            if let Some(declarator) = declarator {
                if let Some(name) = find_first_identifier(source, declarator) {
                    env.set(name, val);
                }
            }
        }
    }
}

fn summarize_expr(source: &str, node: Node<'_>, env: &mut SummaryEnv<'_>) -> TaintExpr {
    match node.kind() {
        "assignment_expression" => {
            let left = node.child_by_field_name("left");
            let right = node.child_by_field_name("right");
            let val = right.map(|r| summarize_expr(source, r, env)).unwrap_or(TaintExpr::Never);
            if let Some(left) = left {
                if let Some(name) = base_identifier(source, left) {
                    env.set(name, val.clone());
                }
            }
            val
        }
        "identifier" => env.get(&node_text(source, node)),
        "call_expression" => summarize_call(source, node, env),
        "subscript_expression" => {
            if base_identifier(source, node).as_deref() == Some("argv") {
                return TaintExpr::Always;
            }
            summarize_children(source, node, env)
        }
        _ => summarize_children(source, node, env),
    }
}

fn summarize_children(source: &str, node: Node<'_>, env: &mut SummaryEnv<'_>) -> TaintExpr {
    let mut out = TaintExpr::Never;
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        out = out.join(summarize_expr(source, child, env));
        if out == TaintExpr::Always {
            break;
        }
    }
    out
}

fn summarize_call(source: &str, node: Node<'_>, env: &mut SummaryEnv<'_>) -> TaintExpr {
    let Some(callee) = node.child_by_field_name("function") else {
        return summarize_children(source, node, env);
    };
    let Some(name) = callee_name(source, callee) else {
        return summarize_children(source, node, env);
    };

    if name == "getenv" {
        return TaintExpr::Always;
    }
    if rules::is_source_function(&name).is_some() {
        // For summary purposes, treat other sources as tainting output too.
        return TaintExpr::Always;
    }

    let args = node.child_by_field_name("arguments");
    let mut arg_vals = Vec::new();
    if let Some(args) = args {
        let mut cursor = args.walk();
        for arg in args.named_children(&mut cursor) {
            arg_vals.push(summarize_expr(source, arg, env));
        }
    }

    if let Some(sum) = env.summaries.get(&name) {
        return apply_summary(&sum.ret, &arg_vals);
    }

    // Unknown function: conservative join of args.
    arg_vals.into_iter().fold(TaintExpr::Never, |acc, v| acc.join(v))
}

fn apply_summary(ret: &ReturnTaint, args: &[TaintExpr]) -> TaintExpr {
    match ret {
        ReturnTaint::Always => TaintExpr::Always,
        ReturnTaint::Never => TaintExpr::Never,
        ReturnTaint::FromParams(params) => {
            let mut out = TaintExpr::Never;
            for &idx in params {
                if let Some(v) = args.get(idx) {
                    out = out.join(v.clone());
                }
            }
            out
        }
    }
}

fn find_first_kind<'a>(node: Node<'a>, kind: &str) -> Option<Node<'a>> {
    if node.kind() == kind {
        return Some(node);
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if let Some(n) = find_first_kind(child, kind) {
            return Some(n);
        }
    }
    None
}

fn find_first_identifier(source: &str, node: Node<'_>) -> Option<String> {
    if node.kind() == "identifier" {
        return Some(node_text(source, node));
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if let Some(id) = find_first_identifier(source, child) {
            return Some(id);
        }
    }
    None
}

fn scan_tree(source: &str, path: &str, tree: &Tree, ctx: &AnalysisCtx) -> Vec<Finding> {
    let root = tree.root_node();
    let mut findings = Vec::new();
    let mut scope = Scope::new(None);
    let registry = crate::rule_engine::RuleRegistry::default_c();
    scan_block(source, root, path, &mut findings, &mut scope, ctx, &registry, false);
    findings
}

fn scan_block(
    source: &str,
    node: Node,
    path: &str,
    findings: &mut Vec<Finding>,
    scope: &mut Scope,
    ctx: &AnalysisCtx,
    registry: &crate::rule_engine::RuleRegistry,
    conditional: bool,
) {
    let kind = node.kind();
    if kind == "translation_unit" || kind == "compound_statement" {
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            scan_stmt(source, child, path, findings, scope, ctx, registry, conditional);
        }
        return;
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        scan_stmt(source, child, path, findings, scope, ctx, registry, conditional);
}
}

fn scan_stmt(
    source: &str,
    node: Node,
    path: &str,
    findings: &mut Vec<Finding>,
    scope: &mut Scope,
    ctx: &AnalysisCtx,
    registry: &crate::rule_engine::RuleRegistry,
    conditional: bool,
) {
    match node.kind() {
        "function_definition" => {
            if let Some(body) = node.child_by_field_name("body") {
                let mut nested = Scope::new(Some(scope));
                scan_block(source, body, path, findings, &mut nested, ctx, registry, false);
            }
            return;
        }
        "declaration" => {
            handle_declaration(source, node, path, findings, scope, ctx, registry, conditional);
            return;
        }
        "expression_statement" => {
            if let Some(expr) = node.named_child(0) {
                scan_expr(source, expr, path, findings, scope, ExprCtx::Normal, ctx, registry, conditional);
            }
            return;
        }
        "return_statement" => {
            if let Some(expr) = node
                .child_by_field_name("argument")
                .or_else(|| node.child_by_field_name("value"))
                .or_else(|| node.named_child(0))
            {
                scan_expr(source, expr, path, findings, scope, ExprCtx::Normal, ctx, registry, conditional);
            }
            return;
        }
        "if_statement" => {
            if let Some(cond) = node.child_by_field_name("condition") {
                scan_expr(source, cond, path, findings, scope, ExprCtx::Normal, ctx, registry, conditional);
            }
            if let Some(cons) = node.child_by_field_name("consequence") {
                scan_stmt(source, cons, path, findings, scope, ctx, registry, true);
            }
            if let Some(alt) = node.child_by_field_name("alternative") {
                scan_stmt(source, alt, path, findings, scope, ctx, registry, true);
            }
            return;
        }
        "for_statement" => {
            if let Some(init) = node
                .child_by_field_name("initializer")
                .or_else(|| node.child_by_field_name("init"))
                .or_else(|| node.child_by_field_name("declaration"))
            {
                if init.kind() == "declaration" {
                    handle_declaration(source, init, path, findings, scope, ctx, registry, conditional);
                } else {
                    scan_expr(source, init, path, findings, scope, ExprCtx::Normal, ctx, registry, conditional);
                }
            }
            if let Some(cond) = node.child_by_field_name("condition") {
                scan_expr(source, cond, path, findings, scope, ExprCtx::Normal, ctx, registry, conditional);
            }
            if let Some(update) = node
                .child_by_field_name("update")
                .or_else(|| node.child_by_field_name("increment"))
            {
                scan_expr(source, update, path, findings, scope, ExprCtx::Normal, ctx, registry, conditional);
            }

            let loop_range = for_loop_range(source, node, scope);
            let mut saved: Option<(String, Option<IntRange>)> = None;
            if let Some((var, r)) = loop_range {
                let old = scope.get(&var).range;
                scope.set_range(&var, Some(r));
                saved = Some((var, old));
            }

            if let Some(body) = node.child_by_field_name("body").or_else(|| node.child_by_field_name("statement"))
            {
                scan_stmt(source, body, path, findings, scope, ctx, registry, true);
            }

            if let Some((var, old)) = saved {
                scope.set_range(&var, old);
            }
            return;
        }
        "while_statement" | "do_statement" | "switch_statement" => {
            if let Some(cond) = node.child_by_field_name("condition") {
                scan_expr(source, cond, path, findings, scope, ExprCtx::Normal, ctx, registry, conditional);
            }
            if let Some(body) = node.child_by_field_name("body").or_else(|| node.child_by_field_name("statement")) {
                scan_stmt(source, body, path, findings, scope, ctx, registry, true);
            }
            return;
        }
        _ => {}
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        scan_stmt(source, child, path, findings, scope, ctx, registry, conditional);
    }
}

fn for_loop_range(source: &str, node: Node, scope: &Scope) -> Option<(String, IntRange)> {
    let cond = node.child_by_field_name("condition")?;
    if cond.kind() != "binary_expression" {
        return None;
    }
    let left = cond.child_by_field_name("left").or_else(|| cond.named_child(0))?;
    let right = cond.child_by_field_name("right").or_else(|| cond.named_child(1))?;
    let var = extract_identifier(source, left)?;
    let bound = expr_range(source, right, scope)?;
    let op = cond.child(1).map(|c| node_text(source, c)).unwrap_or_default();

    // Best-effort init: `i = 0` or `int i = 0`.
    let mut start: Option<i64> = None;
    if let Some(init) = node
        .child_by_field_name("initializer")
        .or_else(|| node.child_by_field_name("init"))
        .or_else(|| node.child_by_field_name("declaration"))
    {
        if init.kind() == "assignment_expression" {
            let il = init.child_by_field_name("left").or_else(|| init.named_child(0));
            let ir = init.child_by_field_name("right").or_else(|| init.named_child(1));
            if let (Some(il), Some(ir)) = (il, ir) {
                if extract_identifier(source, il).as_deref() == Some(var.as_str()) {
                    start = expr_range(source, ir, scope).map(|r| r.min);
                }
            }
        } else if init.kind() == "declaration" {
            let mut cursor = init.walk();
            for child in init.named_children(&mut cursor) {
                if child.kind() == "init_declarator" {
                    let declarator = child.child_by_field_name("declarator");
                    let value = child.child_by_field_name("value");
                    if let (Some(decl), Some(val)) = (declarator, value) {
                        let ids = declarator_idents(source, decl);
                        if ids.iter().any(|id| id == &var) {
                            start = expr_range(source, val, scope).map(|r| r.min);
                            break;
                        }
                    }
                }
            }
        }
    }
    let start = start?;

    let max = match op.trim() {
        "<" => bound.max.saturating_sub(1),
        "<=" => bound.max,
        _ => return None,
    };
    Some((var, IntRange { min: start, max }))
}

fn handle_declaration(
    source: &str,
    node: Node,
    path: &str,
    findings: &mut Vec<Finding>,
    scope: &mut Scope,
    ctx: &AnalysisCtx,
    registry: &crate::rule_engine::RuleRegistry,
    conditional: bool,
) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        // C grammar uses init_declarator inside declaration.
        if child.kind() == "init_declarator" {
            let declarator = child.child_by_field_name("declarator");
            let value = child.child_by_field_name("value");
            if let Some(value) = value {
                scan_expr(source, value, path, findings, scope, ExprCtx::Normal, ctx, registry, conditional);
            }
            let tainted = value
                .map(|v| expr_tainted(source, v, scope, ctx))
                .unwrap_or(false);
            let alloc = value
                .and_then(|v| alloc_from_expr(source, v, ctx))
                .unwrap_or(AllocState::Unknown);
            let mem_alloc = value.and_then(|v| mem_alloc_from_expr(source, v));
            let range = value.and_then(|v| expr_range(source, v, scope));
            if let Some(declarator) = declarator {
                let buf_len = declarator_array_len(source, declarator);
                for name in declarator_idents(source, declarator) {
                    if is_function_pointer_declarator(declarator) {
                        scope.mark_fn_ptr(&name);
                    }
                    let mem_id = if alloc == AllocState::Allocated {
                        mem_alloc.as_ref().map(|m| m.id)
                    } else {
                        None
                    };
                    scope.set(
                        name.clone(),
                        VarInfo {
                            tainted,
                            alloc,
                            buf_len,
                            mem_id,
                            range,
                            taint_meta: None,
                        },
                    );
                    if let Some(m) = mem_alloc.as_ref() {
                        scope.mem_set(
                            m.id,
                            MemInfo {
                                state: AllocState::Allocated,
                                size: m.size,
                            },
                        );
                    }
                    if let Some(value) = value {
                        if let Some(target) = alias_target(source, value) {
                            // `char *p = buf;` → p aliases buf
                            scope.add_alias(&name, &target);
                            // Pointer alias: propagate memory IDs (heap) through variable-to-variable assignments.
                            let target_info = scope.get(&target);
                            if target_info.mem_id.is_some() {
                                let mut info = scope.get(&name);
                                info.mem_id = target_info.mem_id;
                                scope.set(name.clone(), info);
                            }
                        }
                        if let Some(fn_target) = function_alias_target(source, value, scope) {
                            scope.set_fn_alias(&name, &fn_target);
                            scope.mark_fn_ptr(&name);
                        }
                    }
                    if tainted {
                        let meta = taint_meta_from_expr(source, value, scope, ctx, name.as_str())
                            .unwrap_or(TaintMeta { source: None, prev: None });
                        scope.taint_var(&name, meta);
                    }
                }
            }
        }
    }

    // Best-effort: record fixed-size stack arrays like `char buf[16];` even if declarator fields differ.
    annotate_array_decls(source, node, scope);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExprCtx {
    Normal,
    Lhs,
}

fn scan_expr(
    source: &str,
    node: Node,
    path: &str,
    findings: &mut Vec<Finding>,
    scope: &mut Scope,
    ctx: ExprCtx,
    actx: &AnalysisCtx,
    registry: &crate::rule_engine::RuleRegistry,
    conditional: bool,
) {
    // Function pointer resolution debug logging (TEMP).
    // Enable with: FP_DEBUG=1
    if node.kind() == "call_expression" {
        if let Some(callee) = node.child_by_field_name("function") {
            if callee.kind() == "identifier" {
                let name = node_text(source, callee);
                if let Some(resolved) = scope.resolve_fn_alias(&name) {
                    if std::env::var("FP_DEBUG").ok().as_deref() == Some("1") {
                        eprintln!("[FP] {name} -> {resolved}");
                    }
                }
            }
        }
    }

    if node.kind() == "call_expression" || node.kind() == "identifier" || node.kind() == "subscript_expression" {
        let mut fs = registry.check_node(node, actx, scope);
        for f in &mut fs {
            f.conditional = conditional;
        }
        findings.extend(fs);
    }
    // Assignment propagation
    if node.kind() == "assignment_expression" {
        let left = node.child_by_field_name("left");
        let right = node.child_by_field_name("right");
        if let Some(right) = right {
            scan_expr(source, right, path, findings, scope, ExprCtx::Normal, actx, registry, conditional);
        }
        // Still traverse LHS so identifier-level rules (e.g. UAF) can see dereferences like `p[0] = ...`.
        if let Some(left) = left {
            scan_expr(source, left, path, findings, scope, ExprCtx::Lhs, actx, registry, conditional);
        }
        if let (Some(left), Some(right)) = (left, right) {
            let rhs_taint = expr_tainted(source, right, scope, actx);
            let rhs_alloc = alloc_from_expr(source, right, actx)
                .unwrap_or(scope.get(&node_text(source, left)).alloc);
            let rhs_mem_alloc = mem_alloc_from_expr(source, right);
            let rhs_range = expr_range(source, right, scope);
            if left.kind() == "identifier" {
                let left_name = node_text(source, left);
                if let Some(target) = alias_target(source, right) {
                    scope.add_alias(&left_name, &target);
                }
                // Propagate function-pointer-ness across assignment.
                if let Some(src_id) = extract_identifier(source, right) {
                    if scope.is_fn_ptr(&src_id) {
                        scope.mark_fn_ptr(&left_name);
                    }
                }
                if let Some(fn_target) = function_alias_target(source, right, scope) {
                    scope.set_fn_alias(&left_name, &fn_target);
                    scope.mark_fn_ptr(&left_name);
                }

                let mut left_info = scope.get(&left_name);
                left_info.tainted = rhs_taint;
                left_info.alloc = rhs_alloc;
                left_info.range = rhs_range.or(left_info.range);
                if rhs_alloc == AllocState::Allocated {
                    if let Some(ma) = rhs_mem_alloc.as_ref() {
                        left_info.mem_id = Some(ma.id);
                        scope.mem_set(
                            ma.id,
                            MemInfo {
                                state: AllocState::Allocated,
                                size: ma.size,
                            },
                        );
                    }
                } else if let Some(target) = alias_target(source, right) {
                    let target_info = scope.get(&target);
                    if target_info.mem_id.is_some() {
                        left_info.mem_id = target_info.mem_id;
                    }
                }
                scope.set(
                    left_name.clone(),
                    VarInfo {
                        buf_len: left_info.buf_len,
                        taint_meta: None,
                        ..left_info
                    }
                );
                if rhs_taint {
                    let meta = taint_meta_from_expr(source, Some(right), scope, actx, left_name.as_str())
                        .unwrap_or(TaintMeta { source: None, prev: None });
                    scope.taint_var(&left_name, meta);
                }
            }
        }
        return;
    }

    // Calls: sources/sinks
    if node.kind() == "call_expression" {
        apply_call_effects(source, node, path, scope);
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        scan_expr(source, child, path, findings, scope, ctx, actx, registry, conditional);
    }
}

fn apply_call_effects(source: &str, node: Node, path: &str, scope: &mut Scope) {
    let callee = node.child_by_field_name("function");
    let Some(callee) = callee else { return };
    let name = resolved_callee_name(source, callee, scope);
    let Some(name) = name else { return };

    // Handle free() state transitions.
    if name == "free" {
        let arg0 = node.child_by_field_name("arguments").and_then(|a| a.named_child(0));
        if let Some(arg0) = arg0 {
            if let Some(var) = extract_identifier(source, arg0) {
                let mut info = scope.get(&var);
                info.alloc = AllocState::Freed;
                if let Some(id) = info.mem_id {
                    let mut mi = scope.mem_get(id).unwrap_or(MemInfo {
                        state: AllocState::Unknown,
                        size: None,
                    });
                    mi.state = AllocState::Freed;
                    scope.mem_set(id, mi);
                }
                scope.set(var, info);
            }
        }
        return;
    }

    // Source calls: getenv() return taints, scanf/read/recv taint buffers (handled by side-effects below).
    if let Some(src_kind) = rules::is_source_function(&name) {
        match src_kind {
            SourceKind::GetEnv => {
                // Return taint handled by expr_tainted() conservatively.
            }
            SourceKind::ScanfFamily | SourceKind::Read | SourceKind::Recv => {
                // Mark buffer args as tainted.
                if let Some(args) = node.child_by_field_name("arguments") {
                    let mut cursor = args.walk();
                    for (idx, arg) in args.named_children(&mut cursor).enumerate() {
                        // read(fd, buf, n) -> buf is 2nd arg
                        // recv(fd, buf, n, flags) -> buf is 2nd arg
                        // scanf(fmt, &x) -> outputs start at 2nd arg; conservatively taint non-literal args after fmt.
                        let should_taint = match src_kind {
                            SourceKind::Read | SourceKind::Recv => idx == 1,
                            SourceKind::ScanfFamily => idx >= 1,
                            _ => false,
                        };
                        if should_taint {
                            if let Some(id) = extract_identifier(source, arg) {
                                scope.taint_var(
                                    &id,
                                    TaintMeta {
                                        source: Some(TaintSource {
                                            kind: name.clone(),
                                            location: loc(path, node),
                                        }),
                                        prev: None,
                                    },
                                );
                            }
                        }
                    }
                }
            }
            SourceKind::Argv => {}
        }
    }
}

fn loc(path: &str, node: Node) -> Location {
    Location {
        path: path.to_string(),
        line: node.start_position().row + 1,
        column: node.start_position().column + 1,
    }
}

fn taint_meta_from_expr(
    source: &str,
    expr: Option<Node>,
    scope: &Scope,
    ctx: &AnalysisCtx,
    lhs_name: &str,
) -> Option<TaintMeta> {
    let expr = expr?;
    if expr.kind() == "call_expression" {
        let callee = expr.child_by_field_name("function")?;
        let name = callee_name(source, callee)?;
        if rules::is_source_function(&name).is_some() || ctx.summaries.get(&name).is_some() {
            return Some(TaintMeta {
                source: Some(TaintSource {
                    kind: name,
                    location: loc(&ctx.path, expr),
                }),
                prev: None,
            });
        }
    }
    if expr.kind() == "subscript_expression" {
        let base = expr.child_by_field_name("argument").or_else(|| expr.child_by_field_name("left"));
        if base.is_some_and(|b| b.kind() == "identifier" && node_text(source, b) == "argv") {
            return Some(TaintMeta {
                source: Some(TaintSource {
                    kind: "argv".to_string(),
                    location: loc(&ctx.path, expr),
                }),
                prev: None,
            });
        }
    }
    if let Some(prev) = first_tainted_ident(source, expr, scope) {
        if prev != lhs_name {
            return Some(TaintMeta {
                source: None,
                prev: Some(prev),
            });
        }
    }
    None
}

fn first_tainted_ident(source: &str, node: Node, scope: &Scope) -> Option<String> {
    if node.kind() == "identifier" {
        let id = node_text(source, node);
        if scope.get(&id).tainted {
            return Some(id);
        }
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if let Some(id) = first_tainted_ident(source, child, scope) {
            return Some(id);
        }
    }
    None
}

pub(crate) fn tainted_flow_path(
    source: &str,
    expr: Node,
    scope: &Scope,
    ctx: &AnalysisCtx,
    sink: &str,
) -> Option<(Option<Location>, Vec<String>)> {
    if !expr_tainted(source, expr, scope, ctx) {
        return None;
    }

    // Direct sources (call/subscript) show as source → sink.
    if expr.kind() == "call_expression" {
        if let Some(callee) = expr.child_by_field_name("function") {
            if let Some(name) = callee_name(source, callee) {
                if rules::is_source_function(&name).is_some() || ctx.summaries.get(&name).is_some() {
                    return Some((Some(loc(&ctx.path, expr)), vec![name, sink.to_string()]));
                }
            }
        }
    }
    if expr.kind() == "subscript_expression" {
        let base = expr.child_by_field_name("argument").or_else(|| expr.child_by_field_name("left"));
        if base.is_some_and(|b| b.kind() == "identifier" && node_text(source, b) == "argv") {
            return Some((Some(loc(&ctx.path, expr)), vec!["argv".to_string(), sink.to_string()]));
        }
    }

    // Prefer a variable chain if we can attribute taint to an identifier.
    let leaf = if expr.kind() == "identifier" {
        node_text(source, expr)
    } else {
        first_tainted_ident(source, expr, scope)?
    };

    let (src_loc, mut steps) = scope.taint_chain(&leaf);
    steps.push(sink.to_string());
    Some((src_loc, steps))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GuardStrength {
    Weak,
    Strong,
}

/// Best-effort guard detection: if a sink call is inside an `if` branch whose condition looks like
/// a bounds/length check, report `Weak` or `Strong`.
pub(crate) fn guard_strength_for_node(
    source: &str,
    sink_node: Node,
    dst_ident: Option<&str>,
    scope: &Scope,
    ctx: &AnalysisCtx,
) -> Option<GuardStrength> {
    let mut cur = sink_node;
    let mut best: Option<GuardStrength> = None;
    while let Some(p) = cur.parent() {
        if p.kind() == "if_statement" {
            let in_cons = p
                .child_by_field_name("consequence")
                .is_some_and(|c| is_node_within(c, sink_node));
            let in_alt = p
                .child_by_field_name("alternative")
                .is_some_and(|c| is_node_within(c, sink_node));
            if in_cons || in_alt {
                if let Some(cond) = p.child_by_field_name("condition") {
                    if let Some(s) = condition_guard_strength(source, cond, dst_ident, scope, ctx) {
                        best = Some(match (best, s) {
                            (Some(GuardStrength::Strong), _) => GuardStrength::Strong,
                            (_, GuardStrength::Strong) => GuardStrength::Strong,
                            _ => GuardStrength::Weak,
                        });
                    }
                }
            }
        }
        cur = p;
    }
    best
}

fn condition_guard_strength(
    source: &str,
    cond: Node,
    dst_ident: Option<&str>,
    scope: &Scope,
    ctx: &AnalysisCtx,
) -> Option<GuardStrength> {
    let mut any = false;
    let mut strong = false;
    let mut cursor = cond.walk();
    for child in cond.named_children(&mut cursor) {
        if child.kind() == "binary_expression" {
            if let Some(s) = binary_guard_strength(source, child, dst_ident, scope, ctx) {
                any = true;
                strong |= matches!(s, GuardStrength::Strong);
            }
        }
        if let Some(s) = condition_guard_strength(source, child, dst_ident, scope, ctx) {
            any = true;
            strong |= matches!(s, GuardStrength::Strong);
        }
    }
    if strong {
        Some(GuardStrength::Strong)
    } else if any {
        Some(GuardStrength::Weak)
    } else {
        None
    }
}

fn binary_guard_strength(
    source: &str,
    node: Node,
    dst_ident: Option<&str>,
    scope: &Scope,
    ctx: &AnalysisCtx,
) -> Option<GuardStrength> {
    let left = node.child_by_field_name("left")?;
    let right = node.child_by_field_name("right")?;
    let op = binary_op_text(source, left, right)?;

    let (len_expr, bound_expr) = match op.as_str() {
        "<" | "<=" => (left, right),
        ">" | ">=" => (right, left),
        _ => return None,
    };

    if !looks_like_length_expr(source, len_expr) {
        return None;
    }

    if let Some(strong_bound) = bound_strength(source, bound_expr, dst_ident, scope, ctx) {
        return Some(if strong_bound { GuardStrength::Strong } else { GuardStrength::Weak });
    }
    Some(GuardStrength::Weak)
}

fn binary_op_text(source: &str, left: Node, right: Node) -> Option<String> {
    if left.end_byte() >= right.start_byte() {
        return None;
    }
    let between = source.get(left.end_byte()..right.start_byte())?;
    let op = between.split_whitespace().collect::<String>();
    if op.is_empty() {
        None
    } else {
        Some(op)
    }
}

fn looks_like_length_expr(source: &str, node: Node) -> bool {
    match node.kind() {
        "identifier" => true,
        "call_expression" => {
            if let Some(callee) = node.child_by_field_name("function") {
                return callee_name(source, callee).as_deref() == Some("strlen");
            }
            false
        }
        _ => {
            let mut cursor = node.walk();
            let any = node
                .named_children(&mut cursor)
                .any(|c| looks_like_length_expr(source, c));
            any
        }
    }
}

fn bound_strength(
    source: &str,
    node: Node,
    dst_ident: Option<&str>,
    scope: &Scope,
    _ctx: &AnalysisCtx,
) -> Option<bool> {
    // Strong: `sizeof(dst)` or literal bound within known destination capacity.
    if node.kind().contains("sizeof") {
        if let Some(dst) = dst_ident {
            let raw = node_text(source, node);
            if raw.contains(dst) {
                return Some(true);
            }
        }
        return Some(false);
    }
    if node.kind() == "number_literal" {
        if let Some(dst) = dst_ident {
            if let Some(cap) = scope.get(dst).buf_len {
                if let Ok(n) = node_text(source, node).trim().parse::<usize>() {
                    return Some(n <= cap);
                }
            }
        }
        return Some(false);
    }
    // Weak: any identifier-sized bound like `len < size`.
    if node.kind() == "identifier" {
        return Some(false);
    }
    None
}

pub(crate) fn is_string_literal_node(node: Node) -> bool {
    node.kind() == "string_literal" || node.kind() == "string"
}

pub(crate) fn dst_has_pointer_arithmetic(dst: Node) -> bool {
    if dst.kind() == "binary_expression" {
        return true;
    }
    let mut cursor = dst.walk();
    for child in dst.named_children(&mut cursor) {
        if dst_has_pointer_arithmetic(child) {
            return true;
        }
    }
    false
}

pub(crate) fn sprintf_format_is_bounded(source: &str, fmt: Node) -> bool {
    // Heuristic: allow only conversions with fixed max lengths, disallow `%s`, `%n`, and dynamic width/precision.
    let raw = node_text(source, fmt);
    let s = raw.replace("%%", "");
    let mut chars = s.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '%' {
            continue;
        }
        // Read flags/width/precision/length; bail out on '*' (dynamic).
        let mut spec = String::new();
        while let Some(&c) = chars.peek() {
            spec.push(c);
            chars.next();
            if c.is_ascii_alphabetic() {
                break;
            }
        }
        if spec.contains('*') {
            return false;
        }
        let conv = spec.chars().last().unwrap_or('\0');
        match conv {
            'p' | 'd' | 'i' | 'u' | 'x' | 'X' | 'o' | 'c' => {}
            's' | 'n' => return false,
            _ => return false,
        }
    }
    true
}

pub(crate) fn sprintf_max_len(source: &str, fmt: Node, args: &Node) -> Option<usize> {
    // Best-effort upper bound for literal formats without `%s` (unless the corresponding arg is a literal).
    let raw = node_text(source, fmt);
    let stripped = raw.trim();
    let inner = stripped
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .or_else(|| stripped.strip_prefix("L\"").and_then(|s| s.strip_suffix('"')))?;

    let mut total = 0usize;
    let mut arg_index = 2usize; // fmt is arg1; first variadic is arg2
    let bytes = inner.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] != b'%' {
            total += 1;
            i += 1;
            continue;
        }
        // Handle %%
        if i + 1 < bytes.len() && bytes[i + 1] == b'%' {
            total += 1;
            i += 2;
            continue;
        }
        i += 1;
        // Skip flags/width/precision/length (very rough); stop at conversion char.
        let mut saw_star = false;
        while i < bytes.len() {
            let c = bytes[i] as char;
            if c == '*' {
                saw_star = true;
            }
            if c.is_ascii_alphabetic() {
                break;
            }
            i += 1;
        }
        if i >= bytes.len() || saw_star {
            return None;
        }
        let conv = bytes[i] as char;
        let add = match conv {
            'p' => 18, // "0x" + 16 hex (best-effort)
            // Numeric specifiers vary by type/width; don't guess an upper bound here.
            // Returning `None` avoids false positives in "fits in dest" checks.
            'd' | 'i' | 'u' | 'x' | 'X' | 'o' => return None,
            'c' => 1,
            's' => {
                let arg = args.named_child(arg_index)?;
                arg_index += 1;
                string_literal_len(source, arg)?
            }
            'n' => return None,
            _ => return None,
        };
        if conv != 's' {
            arg_index += 1;
        }
        total = total.saturating_add(add);
        i += 1;
    }
    Some(total)
}

pub(crate) fn expr_tainted(source: &str, node: Node, scope: &Scope, actx: &AnalysisCtx) -> bool {
    if is_source_expr(source, node, scope) {
        return true;
    }

    match node.kind() {
        "identifier" => scope.get(&node_text(source, node)).tainted,
        "string_literal" | "string" | "number_literal" | "true" | "false" | "null" => false,
        "subscript_expression" => {
            // argv[i]
            let base = node.child_by_field_name("argument").or_else(|| node.child_by_field_name("left"));
            if base.is_some_and(|b| b.kind() == "identifier" && node_text(source, b) == "argv") {
                return true;
            }
            any_child_tainted(source, node, scope, actx)
        }
        "call_expression" => {
            let callee = node.child_by_field_name("function");
            if let Some(callee) = callee {
                if let Some(name) = callee_name(source, callee) {
                    if name == "getenv" {
                        return true;
                    }
                    if let Some(summary) = actx.summaries.get(&name) {
                        return call_ret_tainted(source, node, scope, actx, summary);
                    }
                }
            }
            // Conservative: taint if any arg tainted.
            let args = node.child_by_field_name("arguments");
            if let Some(args) = args {
                let mut cursor = args.walk();
                for arg in args.named_children(&mut cursor) {
                    if expr_tainted(source, arg, scope, actx) {
                        return true;
                    }
                }
            }
            false
        }
        _ => any_child_tainted(source, node, scope, actx),
    }
}

fn call_ret_tainted(
    source: &str,
    call: Node,
    scope: &Scope,
    actx: &AnalysisCtx,
    summary: &FnSummary,
) -> bool {
    match &summary.ret {
        ReturnTaint::Always => true,
        ReturnTaint::Never => false,
        ReturnTaint::FromParams(params) => {
            let Some(args) = call.child_by_field_name("arguments") else {
                return false;
            };
            for &idx in params {
                if let Some(arg) = args.named_child(idx) {
                    if expr_tainted(source, arg, scope, actx) {
                        return true;
                    }
                }
            }
            false
        }
    }
}

fn any_child_tainted(
    source: &str,
    node: Node,
    scope: &Scope,
    actx: &AnalysisCtx,
) -> bool {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if expr_tainted(source, child, scope, actx) {
            return true;
        }
    }
    false
}

fn is_source_expr(source: &str, node: Node, scope: &Scope) -> bool {
    // argv: treat argv[...] as tainted; argv variable itself is a tainted source.
    if node.kind() == "identifier" && node_text(source, node) == "argv" {
        return true;
    }

    if node.kind() == "call_expression" {
        let callee = node.child_by_field_name("function");
        if let Some(callee) = callee {
            if let Some(name) = callee_name(source, callee) {
                if rules::is_source_function(&name).is_some() {
                    // getenv handled as return-taint; others handled in handle_call side-effects.
                    return name == "getenv";
                }
            }
        }
    }

    // Propagate taint from identifiers.
    if node.kind() == "identifier" {
        return scope.get(&node_text(source, node)).tainted;
    }
    false
}

fn alloc_from_expr(source: &str, node: Node, _actx: &AnalysisCtx) -> Option<AllocState> {
    let mut cur = node;
    loop {
        match cur.kind() {
            "parenthesized_expression" => {
                cur = cur.named_child(0)?;
            }
            "cast_expression" => {
                cur = cur.child_by_field_name("value").or_else(|| cur.named_child(0))?;
            }
            _ => break,
        }
    }
    if cur.kind() != "call_expression" {
        return None;
    }
    let callee = cur.child_by_field_name("function")?;
    let name = callee_name(source, callee)?;
    if matches!(rules::is_sink_function(&name), Some(SinkKind::MallocFamily)) {
        return Some(AllocState::Allocated);
    }
    None
}

#[derive(Debug, Clone, Copy)]
struct MemAlloc {
    id: u64,
    size: Option<usize>,
}

fn mem_alloc_from_expr(source: &str, node: Node) -> Option<MemAlloc> {
    let mut cur = node;
    loop {
        match cur.kind() {
            "parenthesized_expression" => {
                cur = cur.named_child(0)?;
            }
            "cast_expression" => {
                cur = cur.child_by_field_name("value").or_else(|| cur.named_child(0))?;
            }
            _ => break,
        }
    }
    if cur.kind() != "call_expression" {
        return None;
    }
    let callee = cur.child_by_field_name("function")?;
    let name = callee_name(source, callee)?;
    if !matches!(rules::is_sink_function(&name), Some(SinkKind::MallocFamily)) {
        return None;
    }
    let id = alloc_mem_id(cur);
    let size = malloc_size_from_call(source, cur, &name);
    Some(MemAlloc { id, size })
}

fn alloc_mem_id(node: Node) -> u64 {
    // Deterministic per file: use byte offsets to avoid global counters.
    let a = node.start_byte() as u64;
    let b = node.end_byte() as u64;
    a ^ (b << 32)
}

fn malloc_size_from_call(source: &str, call: Node, name: &str) -> Option<usize> {
    let args = call.child_by_field_name("arguments")?;
    match name {
        "malloc" => args.named_child(0).and_then(|n| parse_usize(&node_text(source, n))),
        "realloc" => args.named_child(1).and_then(|n| parse_usize(&node_text(source, n))),
        "calloc" => {
            let a = args.named_child(0).and_then(|n| parse_usize(&node_text(source, n)))?;
            let b = args.named_child(1).and_then(|n| parse_usize(&node_text(source, n)))?;
            a.checked_mul(b)
        }
        _ => None,
    }
}

pub(crate) fn expr_range(source: &str, node: Node, scope: &Scope) -> Option<IntRange> {
    match node.kind() {
        "number_literal" => parse_i64(&node_text(source, node)).map(|n| IntRange { min: n, max: n }),
        "identifier" => scope.get(&node_text(source, node)).range,
        "parenthesized_expression" => node.named_child(0).and_then(|c| expr_range(source, c, scope)),
        "unary_expression" => {
            let op = node.child(0).map(|c| node_text(source, c)).unwrap_or_default();
            let arg = node.child_by_field_name("argument").or_else(|| node.named_child(0))?;
            let r = expr_range(source, arg, scope)?;
            if op.trim() == "-" {
                Some(IntRange { min: -r.max, max: -r.min })
            } else {
                Some(r)
            }
        }
        "binary_expression" => {
            let left = node.child_by_field_name("left").or_else(|| node.named_child(0))?;
            let right = node.child_by_field_name("right").or_else(|| node.named_child(1))?;
            let op = node.child(1).map(|c| node_text(source, c)).unwrap_or_default();
            let l = expr_range(source, left, scope)?;
            let r = expr_range(source, right, scope)?;
            match op.trim() {
                "+" => Some(IntRange { min: l.min.saturating_add(r.min), max: l.max.saturating_add(r.max) }),
                "-" => Some(IntRange { min: l.min.saturating_sub(r.max), max: l.max.saturating_sub(r.min) }),
                _ => None,
            }
        }
        _ => None,
    }
}

fn parse_i64(s: &str) -> Option<i64> {
    let t = s.trim();
    if t.starts_with("0x") || t.starts_with("0X") {
        i64::from_str_radix(t.trim_start_matches("0x").trim_start_matches("0X"), 16).ok()
    } else {
        t.parse::<i64>().ok()
    }
}

fn function_alias_target(source: &str, expr: Node, scope: &Scope) -> Option<String> {
    let id = extract_identifier(source, expr)?;
    if rules::is_sink_function(&id).is_some() || rules::is_source_function(&id).is_some() {
        return Some(id);
    }
    // Simple propagation: fn2 = fn1
    scope.resolve_fn_alias(&id)
}

fn is_function_pointer_declarator(node: Node) -> bool {
    // Heuristic: function pointer declarators contain both a pointer layer and a function declarator.
    let mut saw_ptr = false;
    let mut saw_fn = false;
    let mut stack = vec![node];
    while let Some(n) = stack.pop() {
        match n.kind() {
            "pointer_declarator" => saw_ptr = true,
            "function_declarator" => saw_fn = true,
            _ => {}
        }
        let mut cursor = n.walk();
        for c in n.named_children(&mut cursor) {
            stack.push(c);
        }
    }
    saw_ptr && saw_fn
}

fn declarator_idents(source: &str, node: Node) -> Vec<String> {
    // Keep it simple: find the first identifier inside the declarator.
    let mut out = Vec::new();
    if node.kind() == "identifier" {
        out.push(node_text(source, node));
        return out;
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        out.extend(declarator_idents(source, child));
    }
    out
}

fn declarator_array_len(source: &str, node: Node) -> Option<usize> {
    if node.kind() == "array_declarator" {
        if let Some(size) = node.child_by_field_name("size") {
            if let Some(n) = parse_usize(node_text(source, size).as_str()) {
                return Some(n);
            }
        }
        // Some grammar versions may not expose a `size` field. Fall back to scanning children.
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if let Some(n) = parse_usize(node_text(source, child).as_str()) {
                return Some(n);
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if let Some(n) = declarator_array_len(source, child) {
            return Some(n);
        }
    }
    None
}

fn annotate_array_decls(source: &str, node: Node, scope: &mut Scope) {
    if node.kind() == "array_declarator" {
        if let (Some(name), Some(len)) = (
            declarator_idents(source, node).into_iter().next(),
            declarator_array_len(source, node),
        ) {
            let mut info = scope.get(&name);
            info.buf_len = Some(len);
            scope.set(name, info);
        }
    }

    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        annotate_array_decls(source, child, scope);
    }
}

fn parse_usize(s: &str) -> Option<usize> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return None;
    }
    // Handle simple decimal literals.
    if let Ok(n) = trimmed.parse::<usize>() {
        return Some(n);
    }
    // Handle hex like 0x20.
    if let Some(hex) = trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X")) {
        return usize::from_str_radix(hex, 16).ok();
    }
    None
}

pub(crate) fn base_identifier(source: &str, node: Node) -> Option<String> {
    if node.kind() == "identifier" {
        return Some(node_text(source, node));
    }
    // For `buf + sz` and `&buf[0]`, walk children to find the first identifier.
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if let Some(id) = base_identifier(source, child) {
            return Some(id);
        }
    }
    None
}

fn alias_target(source: &str, node: Node) -> Option<String> {
    match node.kind() {
        "identifier"
        | "subscript_expression"
        | "field_expression"
        | "pointer_expression"
        | "unary_expression"
        | "parenthesized_expression"
        | "cast_expression"
        | "binary_expression" => base_identifier(source, node),
        _ => None,
    }
}

pub(crate) fn string_literal_len(source: &str, node: Node) -> Option<usize> {
    if node.kind() != "string_literal" && node.kind() != "string" {
        return None;
    }
    let raw = node_text(source, node);
    // Best-effort: count bytes between quotes for simple `"..."` literals.
    // We intentionally ignore escapes here; it's a conservative/heuristic fit-check.
    let stripped = raw.trim();
    let inner = stripped
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .or_else(|| stripped.strip_prefix("L\"").and_then(|s| s.strip_suffix('"')))?;
    Some(inner.len())
}

pub(crate) fn is_const_copy_safe(source: &str, dst: Node, src: Node, scope: &Scope) -> bool {
    let Some(dst_id) = base_identifier(source, dst) else { return false };
    let info = scope.get(&dst_id);
    let Some(cap) = info.buf_len else { return false };
    let Some(n) = string_literal_len(source, src) else { return false };
    // Include the null terminator.
    (n + 1) <= cap
}

fn extract_identifier(source: &str, node: Node) -> Option<String> {
    if node.kind() == "identifier" {
        return Some(node_text(source, node));
    }
    // Handle &x or *x patterns (unary_expression, pointer_expression).
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if let Some(id) = extract_identifier(source, child) {
            return Some(id);
        }
    }
    None
}

pub(crate) fn callee_name(source: &str, node: Node) -> Option<String> {
    match node.kind() {
        "identifier" => Some(node_text(source, node)),
        "field_expression" => node
            .child_by_field_name("field")
            .map(|f| node_text(source, f)),
        "scoped_identifier" | "qualified_identifier" => node
            .child_by_field_name("name")
            .or_else(|| node.named_child(0))
            .map(|n| node_text(source, n)),
        _ => None,
    }
}

pub(crate) fn resolved_callee_name(source: &str, node: Node, scope: &Scope) -> Option<String> {
    let direct = callee_name(source, node)?;
    if let Some(mapped) = scope.resolve_fn_alias(&direct) {
        return Some(mapped);
    }
    Some(direct)
}

pub(crate) fn node_text(source: &str, node: Node) -> String {
    source
        .get(node.byte_range())
        .unwrap_or("")
        .to_string()
}

pub(crate) fn single_line(s: String) -> String {
    let collapsed = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.len() > 200 {
        format!("{}…", &collapsed[..199])
    } else {
        collapsed
    }
}

pub(crate) fn is_node_within(container: Node, needle: Node) -> bool {
    needle.start_byte() >= container.start_byte() && needle.end_byte() <= container.end_byte()
}
