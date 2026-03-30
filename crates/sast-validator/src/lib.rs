use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};

use sast_core::{Confidence, Finding, Language, Severity};
use tree_sitter::{Node, Parser, Tree};

#[cfg(test)]
mod tests;

#[derive(Debug, Clone)]
pub struct AstFile {
    pub path: String,
    pub source: String,
    pub tree: Tree,
    pub language: Language,
    line_starts: Vec<usize>,
}

pub type AstMap = BTreeMap<String, AstFile>;

#[derive(Debug, Default, Clone)]
pub struct CallGraph {
    // Node ids are "path::fn_name".
    pub edges: BTreeMap<String, BTreeSet<String>>,
}

#[derive(Debug, Clone)]
struct FuncInfo {
    id: String,
    file: String,
    name: String,
    param_names: Vec<String>,
    body_range: (usize, usize),
    assigns: Vec<Assign>,
    returns: Vec<Ret>,
    callsites: Vec<CallSite>,
}

#[derive(Debug, Clone)]
struct Cfg {
    entry: usize,
    nodes: Vec<CfgNode>,
    edges: Vec<Vec<CfgEdge>>,
}

#[derive(Debug, Clone)]
struct CfgNode {
    start: usize,
    end: usize,
    kind: String,
}

#[derive(Debug, Clone)]
struct CfgEdge {
    to: usize,
    constraints: Vec<Constraint>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Constraint {
    VarEq { name: String, value: bool },
    PtrNonNull { name: String },
    PtrNull { name: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
struct Constraints {
    vars: BTreeMap<String, bool>,
    ptrs: BTreeMap<String, bool>, // true=non-null, false=null
}

#[derive(Clone, Debug)]
struct BitSet {
    words: Vec<u64>,
}

impl BitSet {
    fn new_all(nbits: usize) -> Self {
        let nwords = (nbits + 63) / 64;
        let mut words = vec![!0u64; nwords];
        // clear high bits
        let extra = nwords * 64 - nbits;
        if extra > 0 {
            let mask = (!0u64) >> extra;
            if let Some(last) = words.last_mut() {
                *last &= mask;
            }
        }
        Self { words }
    }

    fn new_empty(nbits: usize) -> Self {
        let nwords = (nbits + 63) / 64;
        Self {
            words: vec![0u64; nwords],
        }
    }

    fn insert(&mut self, bit: usize) {
        let w = bit / 64;
        let b = bit % 64;
        self.words[w] |= 1u64 << b;
    }

    fn contains(&self, bit: usize) -> bool {
        let w = bit / 64;
        let b = bit % 64;
        (self.words[w] & (1u64 << b)) != 0
    }

    fn intersect_with(&mut self, other: &BitSet) {
        for (a, b) in self.words.iter_mut().zip(other.words.iter()) {
            *a &= *b;
        }
    }

    fn eq(&self, other: &BitSet) -> bool {
        self.words == other.words
    }
}

fn compute_dominators(cfg: &Cfg) -> Vec<BitSet> {
    let n = cfg.nodes.len();
    let mut preds: Vec<Vec<usize>> = vec![Vec::new(); n];
    for (from, outs) in cfg.edges.iter().enumerate() {
        for e in outs {
            preds[e.to].push(from);
        }
    }

    let mut dom: Vec<BitSet> = vec![BitSet::new_all(n); n];
    dom[cfg.entry] = BitSet::new_empty(n);
    dom[cfg.entry].insert(cfg.entry);

    let mut changed = true;
    while changed {
        changed = false;
        for i in 0..n {
            if i == cfg.entry {
                continue;
            }
            let mut new = BitSet::new_all(n);
            if preds[i].is_empty() {
                // unreachable: only dominates itself
                new = BitSet::new_empty(n);
            } else {
                for &p in &preds[i] {
                    new.intersect_with(&dom[p]);
                }
            }
            new.insert(i);
            if !new.eq(&dom[i]) {
                dom[i] = new;
                changed = true;
            }
        }
    }
    dom
}

impl Constraints {
    fn apply_all(&mut self, cs: &[Constraint]) -> bool {
        for c in cs {
            if !self.apply(c) {
                return false;
            }
        }
        true
    }

    fn apply(&mut self, c: &Constraint) -> bool {
        match c {
            Constraint::VarEq { name, value } => match self.vars.get(name) {
                Some(v) if v != value => false,
                _ => {
                    self.vars.insert(name.clone(), *value);
                    true
                }
            },
            Constraint::PtrNonNull { name } => match self.ptrs.get(name) {
                Some(v) if !*v => false,
                _ => {
                    self.ptrs.insert(name.clone(), true);
                    true
                }
            },
            Constraint::PtrNull { name } => match self.ptrs.get(name) {
                Some(v) if *v => false,
                _ => {
                    self.ptrs.insert(name.clone(), false);
                    true
                }
            },
        }
    }
}
#[derive(Debug, Clone)]
struct Assign {
    pos: usize,
    lhs: String,
    rhs: (usize, usize),
}

#[derive(Debug, Clone)]
struct Ret {
    pos: usize,
    expr: (usize, usize),
}

#[derive(Debug, Clone)]
struct CallSite {
    pos: usize,
    callee: String,
    args: Vec<(usize, usize)>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Atom {
    Source { kind: String, file: String, line: usize, col: usize },
    Var(String),
    Param(usize),
    Ret(String),
}

#[derive(Debug)]
struct ProgramIndex<'a> {
    files: &'a AstMap,
    funcs: HashMap<String, FuncInfo>,
    by_name: HashMap<String, Vec<String>>,
    callers: HashMap<String, Vec<(String, CallSite)>>, // callee name -> [(caller func id, callsite)]
    cfg_cache: HashMap<String, Cfg>,
    alias_cache: HashMap<String, AliasSets>,
    dom_cache: HashMap<String, Vec<BitSet>>,
}

#[derive(Debug, Clone)]
struct AliasSets {
    parent: HashMap<String, String>,
}

impl AliasSets {
    fn new() -> Self {
        Self { parent: HashMap::new() }
    }

    fn find(&mut self, x: &str) -> String {
        let p = self.parent.get(x).cloned().unwrap_or_else(|| x.to_string());
        if p == x {
            self.parent.insert(x.to_string(), x.to_string());
            return x.to_string();
        }
        let root = self.find(&p);
        self.parent.insert(x.to_string(), root.clone());
        root
    }

    fn union(&mut self, a: &str, b: &str) {
        let ra = self.find(a);
        let rb = self.find(b);
        if ra != rb {
            self.parent.insert(ra, rb);
        }
    }

    fn group(&mut self, x: &str) -> Vec<String> {
        let root = self.find(x);
        let mut out = Vec::new();
        let keys: Vec<String> = self.parent.keys().cloned().collect();
        for k in keys {
            if self.find(&k) == root {
                out.push(k);
            }
        }
        if out.is_empty() {
            out.push(x.to_string());
        }
        out
    }
}

pub fn parse_file(path: &str, source: &str, language: Language) -> Option<AstFile> {
    if !matches!(language, Language::C | Language::Cpp) {
        return None;
    }

    let mut parser = Parser::new();
    let lang = match language {
        Language::C => tree_sitter_c::LANGUAGE,
        Language::Cpp => tree_sitter_cpp::LANGUAGE,
        _ => return None,
    };
    parser.set_language(&lang.into()).ok()?;
    let tree = parser.parse(source, None)?;

    Some(AstFile {
        path: path.to_string(),
        source: source.to_string(),
        tree,
        language,
        line_starts: line_starts(source),
    })
}

pub fn build_call_graph(ast_map: &AstMap) -> CallGraph {
    let mut cg = CallGraph::default();
    for file in ast_map.values() {
        let root = file.tree.root_node();
        let mut stack = vec![root];
        while let Some(node) = stack.pop() {
            if node.kind() == "function_definition" {
                if let Some((fn_name, body)) = function_name_and_body(&file.source, node) {
                    let caller = fn_id(&file.path, &fn_name);
                    let mut cursor = body.walk();
                    for child in body.named_children(&mut cursor) {
                        collect_calls(&file.source, child, &mut |callee| {
                            cg.edges.entry(caller.clone()).or_default().insert(fn_id(&file.path, &callee));
                        });
                    }
                }
            }
            let mut cursor = node.walk();
            for child in node.named_children(&mut cursor) {
                stack.push(child);
            }
        }
    }
    cg
}

impl<'a> ProgramIndex<'a> {
    fn new(files: &'a AstMap) -> Self {
        Self {
            files,
            funcs: HashMap::new(),
            by_name: HashMap::new(),
            callers: HashMap::new(),
            cfg_cache: HashMap::new(),
            alias_cache: HashMap::new(),
            dom_cache: HashMap::new(),
        }
    }

    fn build(&mut self) {
        for file in self.files.values() {
            let root = file.tree.root_node();
            let mut stack = vec![root];
            while let Some(node) = stack.pop() {
                if node.kind() == "function_definition" {
                    if let Some(info) = self.extract_function(file, node) {
                        self.by_name.entry(info.name.clone()).or_default().push(info.id.clone());
                        for cs in &info.callsites {
                            self.callers
                                .entry(cs.callee.clone())
                                .or_default()
                                .push((info.id.clone(), cs.clone()));
                        }
                        self.funcs.insert(info.id.clone(), info);
                    }
                }
                let mut cursor = node.walk();
                for child in node.named_children(&mut cursor) {
                    stack.push(child);
                }
            }
        }

        // Build per-function caches for state-based validation.
        let func_ids: Vec<String> = self.funcs.keys().cloned().collect();
        for fid in func_ids {
            if let Some(aliases) = self.build_alias_sets(&fid) {
                self.alias_cache.insert(fid.clone(), aliases);
            }
            if let Some(cfg) = self.build_cfg(&fid) {
                let dom = compute_dominators(&cfg);
                self.dom_cache.insert(fid.clone(), dom);
                self.cfg_cache.insert(fid.clone(), cfg);
            }
        }
    }

    fn extract_function(&self, file: &AstFile, fn_node: Node) -> Option<FuncInfo> {
        let (name, body) = function_name_and_body(&file.source, fn_node)?;
        let params = function_params(&file.source, fn_node);
        let id = fn_id(&file.path, &name);

        let mut assigns = Vec::new();
        let mut returns = Vec::new();
        let mut callsites = Vec::new();
        let mut stack = vec![body];
        while let Some(n) = stack.pop() {
            match n.kind() {
                "assignment_expression" => {
                    let left = n.child_by_field_name("left");
                    let right = n.child_by_field_name("right");
                    if let (Some(l), Some(r)) = (left, right) {
                        if let Some(lhs) = var_key(&file.source, l) {
                            assigns.push(Assign {
                                pos: n.start_byte(),
                                lhs,
                                rhs: (r.start_byte(), r.end_byte()),
                            });
                        }
                    }
                }
                "init_declarator" => {
                    let declarator = n.child_by_field_name("declarator");
                    let value = n.child_by_field_name("value");
                    if let (Some(decl), Some(val)) = (declarator, value) {
                        let mut cursor = decl.walk();
                        for ch in decl.named_children(&mut cursor) {
                            if ch.kind() == "identifier" {
                                assigns.push(Assign {
                                    pos: n.start_byte(),
                                    lhs: text(&file.source, ch).to_string(),
                                    rhs: (val.start_byte(), val.end_byte()),
                                });
                            }
                        }
                    }
                }
                "return_statement" => {
                    if let Some(expr) = n.child_by_field_name("argument").or_else(|| n.named_child(0)) {
                        returns.push(Ret {
                            pos: n.start_byte(),
                            expr: (expr.start_byte(), expr.end_byte()),
                        });
                    }
                }
                "call_expression" => {
                    if let Some((callee, args)) = callsite_info(&file.source, n) {
                        callsites.push(CallSite {
                            pos: n.start_byte(),
                            callee,
                            args,
                        });
                    }
                }
                _ => {}
            }
            let mut cursor = n.walk();
            for child in n.named_children(&mut cursor) {
                stack.push(child);
            }
        }
        assigns.sort_by_key(|a| a.pos);
        returns.sort_by_key(|r| r.pos);
        callsites.sort_by_key(|c| c.pos);

        Some(FuncInfo {
            id,
            file: file.path.clone(),
            name,
            param_names: params,
            body_range: (body.start_byte(), body.end_byte()),
            assigns,
            returns,
            callsites,
        })
    }

    fn build_alias_sets(&self, func_id: &str) -> Option<AliasSets> {
        let finfo = self.funcs.get(func_id)?;
        let file = self.files.get(&finfo.file)?;
        let mut aliases = AliasSets::new();

        // Seed with params.
        for p in &finfo.param_names {
            aliases.find(p);
        }

        for a in &finfo.assigns {
            let rhs = node_for_range(file, a.rhs.0, a.rhs.1)?;
            // Only union simple identifier-to-identifier assignments.
            if rhs.kind() == "identifier" {
                aliases.union(&a.lhs, text(&file.source, rhs));
            }
        }
        Some(aliases)
    }

    fn build_cfg(&self, func_id: &str) -> Option<Cfg> {
        let finfo = self.funcs.get(func_id)?;
        let file = self.files.get(&finfo.file)?;
        let body = node_for_range(file, finfo.body_range.0, finfo.body_range.1)?;

        let mut nodes: Vec<CfgNode> = Vec::new();
        let mut edges: Vec<Vec<CfgEdge>> = Vec::new();

        fn new_node(nodes: &mut Vec<CfgNode>, edges: &mut Vec<Vec<CfgEdge>>, start: usize, end: usize, kind: &str) -> usize {
            let id = nodes.len();
            nodes.push(CfgNode {
                start,
                end,
                kind: kind.to_string(),
            });
            edges.push(Vec::new());
            id
        }

        fn link(edges: &mut [Vec<CfgEdge>], froms: &[usize], to: usize) {
            for &f in froms {
                edges[f].push(CfgEdge { to, constraints: Vec::new() });
            }
        }

        fn build_stmt(
            stmt: Node,
            nodes: &mut Vec<CfgNode>,
            edges: &mut Vec<Vec<CfgEdge>>,
            source: &str,
        ) -> Option<(usize, Vec<usize>)> {
            match stmt.kind() {
                "compound_statement" => {
                    let mut cursor = stmt.walk();
                    let mut stmts: Vec<Node> = stmt.named_children(&mut cursor).collect();
                    if stmts.is_empty() {
                        let id = new_node(nodes, edges, stmt.start_byte(), stmt.end_byte(), "empty");
                        return Some((id, vec![id]));
                    }
                    let mut entry: Option<usize> = None;
                    let mut exits: Vec<usize> = Vec::new();
                    for s in stmts.drain(..) {
                        let (e, x) = build_stmt(s, nodes, edges, source)?;
                        if entry.is_none() {
                            entry = Some(e);
                        }
                        if !exits.is_empty() {
                            link(edges, &exits, e);
                        }
                        exits = x;
                    }
                    Some((entry?, exits))
                }
                "if_statement" => {
                    let cond = stmt.child_by_field_name("condition").unwrap_or(stmt);
                    let cond_id = new_node(nodes, edges, cond.start_byte(), cond.end_byte(), "if_cond");
                    let (then_cs, else_cs) = condition_constraints(source, cond);

                    let then_node = stmt.child_by_field_name("consequence")?;
                    let (then_entry, then_exits) = build_stmt(then_node, nodes, edges, source)?;
                    edges[cond_id].push(CfgEdge { to: then_entry, constraints: then_cs });

                    let mut exits = then_exits;
                    if let Some(alt) = stmt.child_by_field_name("alternative") {
                        let (else_entry, else_exits) = build_stmt(alt, nodes, edges, source)?;
                        edges[cond_id].push(CfgEdge { to: else_entry, constraints: else_cs });
                        exits.extend(else_exits);
                    } else {
                        // No else: create an explicit empty else node so we can attach else-constraints.
                        let else_id = new_node(nodes, edges, cond.end_byte(), cond.end_byte(), "if_else_fallthrough");
                        edges[cond_id].push(CfgEdge { to: else_id, constraints: else_cs });
                        exits.push(else_id);
                    }
                    Some((cond_id, exits))
                }
                "while_statement" => {
                    let cond = stmt.child_by_field_name("condition").unwrap_or(stmt);
                    let cond_id = new_node(nodes, edges, cond.start_byte(), cond.end_byte(), "while_cond");
                    let body = stmt.child_by_field_name("body")?;
                    let (body_entry, body_exits) = build_stmt(body, nodes, edges, source)?;
                    edges[cond_id].push(CfgEdge { to: body_entry, constraints: Vec::new() });
                    // back-edge
                    for ex in body_exits {
                        edges[ex].push(CfgEdge { to: cond_id, constraints: Vec::new() });
                    }
                    // exit when cond false: cond flows to next statement
                    Some((cond_id, vec![cond_id]))
                }
                "for_statement" => {
                    let cond = stmt.child_by_field_name("condition").unwrap_or(stmt);
                    let cond_id = new_node(nodes, edges, cond.start_byte(), cond.end_byte(), "for_cond");
                    let body = stmt.child_by_field_name("body")?;
                    let (body_entry, body_exits) = build_stmt(body, nodes, edges, source)?;
                    edges[cond_id].push(CfgEdge { to: body_entry, constraints: Vec::new() });
                    for ex in body_exits {
                        edges[ex].push(CfgEdge { to: cond_id, constraints: Vec::new() });
                    }
                    Some((cond_id, vec![cond_id]))
                }
                "return_statement" => {
                    let id = new_node(nodes, edges, stmt.start_byte(), stmt.end_byte(), "return");
                    Some((id, Vec::new()))
                }
                _ => {
                    let id = new_node(nodes, edges, stmt.start_byte(), stmt.end_byte(), stmt.kind());
                    Some((id, vec![id]))
                }
            }
        }

        let (entry, exits) = build_stmt(body, &mut nodes, &mut edges, &file.source)?;
        let _ = exits;
        Some(Cfg { entry, nodes, edges })
    }

    fn validate_taint_path(&self, finding: &Finding) -> Option<(Vec<String>, Vec<String>)> {
        let file = self.files.get(&finding.location.path)?;
        let sink_off = offset_for(file, finding.location.line, finding.location.column)?;
        let root = file.tree.root_node();
        let node = node_at_byte(root, sink_off)?;
        let call = ancestor_of_kind(node, "call_expression")?;

        let (callee_name, args_ranges) = callsite_info(&file.source, call)?;
        let sink_loc = loc_str(file, call.start_byte());

        let func_name = find_containing_function(file, sink_off)?;
        let func_id = fn_id(&file.path, &func_name);
        let finfo = self.funcs.get(&func_id)?;

        let arg_positions = finding
            .vuln_context
            .as_ref()
            .and_then(|v| v.arg_positions.clone())
            .unwrap_or_else(|| vec![0]);

        let mut notes = Vec::new();
        let mut best: Option<Vec<String>> = None;

        for pos in arg_positions {
            let Some((s, e)) = args_ranges.get(pos).copied() else { continue };
            let arg_node = node_for_range(file, s, e)?;
            let atoms = expr_atoms(file, finfo, arg_node);
            for atom in atoms {
                let mut visited = HashSet::new();
                if let Some(mut p) = self.dfs_atom(&func_id, call.start_byte(), &atom, 0, &mut visited) {
                    // append sink at end
                    p.push(format!("{callee_name}@{sink_loc}"));
                    best = Some(p);
                    notes.push("concrete_source_to_sink_path_confirmed".to_string());
                    break;
                }
            }
            if best.is_some() {
                break;
            }
        }

        best.map(|p| (p, notes))
    }

    fn dfs_atom(
        &self,
        func_id: &str,
        use_pos: usize,
        atom: &Atom,
        depth: usize,
        visited: &mut HashSet<(String, usize, Atom)>,
    ) -> Option<Vec<String>> {
        if depth > 64 {
            return None;
        }
        let key = (func_id.to_string(), use_pos, atom.clone());
        if !visited.insert(key) {
            return None;
        }

        match atom {
            Atom::Source { kind, file, line, col } => {
                return Some(vec![format!("{kind}@{file}:{line}:{col}")]);
            }
            Atom::Var(name) => {
                let finfo = self.funcs.get(func_id)?;
                let file = self.files.get(&finfo.file)?;
                let def = latest_def(&finfo.assigns, name, use_pos)?;
                let rhs_node = node_for_range(file, def.rhs.0, def.rhs.1)?;
                let rhs_atoms = expr_atoms(file, finfo, rhs_node);
                for ra in rhs_atoms {
                    if let Some(mut p) = self.dfs_atom(func_id, def.pos, &ra, depth + 1, visited) {
                        let loc = loc_str(file, def.pos);
                        p.push(format!("{}@{} {}", finfo.name, loc, name));
                        return Some(p);
                    }
                }
                None
            }
            Atom::Ret(callee) => {
                // Follow return dependencies within any matching callee definition.
                let Some(candidates) = self.by_name.get(callee) else { return None };
                for cid in candidates {
                    let cinfo = self.funcs.get(cid)?;
                    let cfile = self.files.get(&cinfo.file)?;
                    for r in &cinfo.returns {
                        let expr_node = node_for_range(cfile, r.expr.0, r.expr.1)?;
                        let atoms = expr_atoms(cfile, cinfo, expr_node);
                        for a in atoms {
                            let mut visited2 = visited.clone();
                            if let Some(mut p) = self.dfs_atom(cid, r.pos, &a, depth + 1, &mut visited2) {
                                let loc = loc_str(cfile, r.pos);
                                p.push(format!("{}@{} return", cinfo.name, loc));
                                *visited = visited2;
                                return Some(p);
                            }
                        }
                    }
                }
                None
            }
            Atom::Param(idx) => {
                // Walk backwards to callers and their actual args.
                let finfo = self.funcs.get(func_id)?;
                let Some(cs) = self.callers.get(&finfo.name) else { return None };
                for (caller_id, callsite) in cs.iter().take(24) {
                    let cinfo = self.funcs.get(caller_id)?;
                    let cfile = self.files.get(&cinfo.file)?;
                    let Some((s, e)) = callsite.args.get(*idx).copied() else { continue };
                    let arg_node = node_for_range(cfile, s, e)?;
                    let atoms = expr_atoms(cfile, cinfo, arg_node);
                    for a in atoms {
                        let mut visited2 = visited.clone();
                        if let Some(mut p) = self.dfs_atom(caller_id, callsite.pos, &a, depth + 1, &mut visited2) {
                            let loc = loc_str(cfile, callsite.pos);
                            p.push(format!("{}@{} arg{}", cinfo.name, loc, idx));
                            *visited = visited2;
                            return Some(p);
                        }
                    }
                }
                None
            }
        }
    }

    fn validate_double_free_state(&self, finding: &Finding) -> Option<StateValidation> {
        let (func_id, target_stmt) = self.find_function_and_stmt(finding)?;
        let (aliases, cfg, file) = self.cfg_and_aliases(&func_id)?;

        // Identify pointer variable for this free() call.
        let sink_off = offset_for(file, finding.location.line, finding.location.column)?;
        let call = ancestor_of_kind(node_at_byte(file.tree.root_node(), sink_off)?, "call_expression")?;
        let (callee, args) = callsite_info(&file.source, call)?;
        if callee != "free" {
            return None;
        }
        let (s, e) = *args.get(0)?;
        let arg = node_for_range(file, s, e)?;
        let var = var_key(&file.source, arg)?;
        let mut aliases = aliases.clone();
        let vars = aliases.group(&var);
        // Prefer dominance-guaranteed validation; fall back to feasible path.
        if let Some(p) =
            self.dominance_state_validate(&func_id, &cfg, file, &vars, target_stmt, StateGoal::DoubleFree)
        {
            return Some(StateValidation {
                confidence: Confidence::High,
                path: p,
                notes: vec!["dominance_confirmed".to_string()],
            });
        }
        if let Some(p) = self.bfs_state_validate(&cfg, file, &vars, target_stmt, StateGoal::DoubleFree) {
            if std::env::var("SAST_VALIDATOR_DEBUG").ok().as_deref() == Some("1") {
                eprintln!(
                    "[validator] feasible double-free path found but no dominance at stmt {}",
                    target_stmt
                );
            }
            return Some(StateValidation {
                confidence: Confidence::Medium,
                path: p,
                notes: vec!["feasible_path_confirmed".to_string()],
            });
        }
        None
    }

    fn validate_uaf_state(&self, finding: &Finding) -> Option<StateValidation> {
        let (func_id, target_stmt) = self.find_function_and_stmt(finding)?;
        let (aliases, cfg, file) = self.cfg_and_aliases(&func_id)?;

        // Find an identifier at the use site.
        let sink_off = offset_for(file, finding.location.line, finding.location.column)?;
        let node = node_at_byte(file.tree.root_node(), sink_off)?;
        let mut cur = node;
        let mut id: Option<String> = None;
        loop {
            if cur.kind() == "identifier" {
                id = Some(text(&file.source, cur).to_string());
                break;
            }
            cur = cur.parent()?;
        }
        let id = id?;

        let mut aliases = aliases.clone();
        let vars = aliases.group(&id);
        // Prefer dominance-guaranteed validation; fall back to feasible path.
        if let Some(p) =
            self.dominance_state_validate(&func_id, &cfg, file, &vars, target_stmt, StateGoal::UseAfterFree)
        {
            return Some(StateValidation {
                confidence: Confidence::High,
                path: p,
                notes: vec!["dominance_confirmed".to_string()],
            });
        }
        if let Some(p) = self.bfs_state_validate(&cfg, file, &vars, target_stmt, StateGoal::UseAfterFree) {
            if std::env::var("SAST_VALIDATOR_DEBUG").ok().as_deref() == Some("1") {
                eprintln!(
                    "[validator] feasible UAF path found but no dominance at stmt {}",
                    target_stmt
                );
            }
            return Some(StateValidation {
                confidence: Confidence::Medium,
                path: p,
                notes: vec!["feasible_path_confirmed".to_string()],
            });
        }
        None
    }

    fn validate_structural(&self, finding: &Finding) -> Option<(Confidence, Option<Vec<String>>, Vec<String>)> {
        let mut notes = Vec::new();
        let file = self.files.get(&finding.location.path)?;

        // Only validate high-risk structural patterns without external input:
        // - pointer arithmetic destinations for sprintf/memcpy/etc
        // - unsafe APIs without bounds checks
        if finding.rule_id.starts_with("c.buffer_overflow") {
            if finding.guarded {
                return None;
            }

            let sink_off = offset_for(file, finding.location.line, finding.location.column)?;
            let root = file.tree.root_node();
            let node = node_at_byte(root, sink_off)?;
            let call = ancestor_of_kind(node, "call_expression")?;
            let (callee, args) = callsite_info(&file.source, call)?;

            let dangerous = matches!(callee.as_str(), "sprintf" | "strcpy" | "strcat" | "memcpy" | "memset" | "gets");
            if !dangerous {
                return None;
            }

            // Inspect destination argument for pointer arithmetic (`buf + off`, `buf+off`, etc.).
            let dest_ptr_arith = args
                .get(0)
                .and_then(|(s, e)| node_for_range(file, *s, *e))
                .is_some_and(|n| contains_pointer_arithmetic(n, &file.source));

            let mut path = None;
            if dest_ptr_arith || finding.rule_id.contains("pointer_arithmetic") || finding.implicit_risk {
                notes.push("structural_overflow_no_bounds_check".to_string());
                let loc = loc_str(file, call.start_byte());
                path = Some(vec![format!("{callee}@{loc}")]);
                return Some((Confidence::High, path, notes));
            }

            // Generic unsafe API usage without bounds checks.
            notes.push("validated_by_pattern".to_string());
            let loc = loc_str(file, call.start_byte());
            path = Some(vec![format!("{callee}@{loc}")]);
            return Some((Confidence::Medium, path, notes));
        }

        None
    }

    fn find_function_and_stmt(&self, finding: &Finding) -> Option<(String, usize)> {
        let file = self.files.get(&finding.location.path)?;
        let off = offset_for(file, finding.location.line, finding.location.column)?;
        let fn_name = find_containing_function(file, off)?;
        let func_id = fn_id(&file.path, &fn_name);
        let cfg = self.cfg_cache.get(&func_id)?;
        let stmt = cfg
            .nodes
            .iter()
            .enumerate()
            .find(|(_, n)| off >= n.start && off < n.end)
            .map(|(i, _)| i)?;
        Some((func_id, stmt))
    }

    fn cfg_and_aliases(&self, func_id: &str) -> Option<(AliasSets, Cfg, &AstFile)> {
        let file_path = func_id.split("::").next()?.to_string();
        let file = self.files.get(&file_path)?;
        let cfg = self.cfg_cache.get(func_id)?.clone();
        let aliases = self.alias_cache.get(func_id)?.clone();
        Some((aliases, cfg, file))
    }

    fn dominators(&self, func_id: &str) -> Option<&Vec<BitSet>> {
        self.dom_cache.get(func_id)
    }

    fn bfs_state_validate(
        &self,
        cfg: &Cfg,
        file: &AstFile,
        vars: &[String],
        target_stmt: usize,
        goal: StateGoal,
    ) -> Option<Vec<String>> {
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        enum FreedState {
            NotFreed,
            Freed,
        }

        #[derive(Clone, Debug, PartialEq, Eq, Hash)]
        struct St {
            node: usize,
            freed: FreedState,
            constraints: Constraints,
        }

        let varset: HashSet<String> = vars.iter().cloned().collect();
        let mut q = VecDeque::new();
        let mut seen: HashSet<St> = HashSet::new();
        // Track witness: for each state, the last free byte position on that path.
        let mut free_at: HashMap<St, Option<usize>> = HashMap::new();

        let start = St {
            node: cfg.entry,
            freed: FreedState::NotFreed,
            constraints: Constraints::default(),
        };
        q.push_back(start.clone());
        seen.insert(start.clone());
        free_at.insert(start, None);

        while let Some(st) = q.pop_front() {
            let node = &cfg.nodes[st.node];
            let stmt = node_for_range(file, node.start, node.end)?;

            // Transfer.
            let mut freed = st.freed;
            let mut cur_free_at = *free_at.get(&st).unwrap_or(&None);
            let cons = st.constraints.clone();

            // Allocation/reset clears freed state.
            if stmt_has_alloc_reset(stmt, &file.source, &varset) {
                freed = FreedState::NotFreed;
                cur_free_at = None;
            }

            // Free events.
            if let Some(free_pos) = stmt_free_pos(stmt, &file.source, &varset) {
                match freed {
                    FreedState::NotFreed => {
                        freed = FreedState::Freed;
                        cur_free_at = Some(free_pos);
                    }
                    FreedState::Freed => {
                        if goal == StateGoal::DoubleFree && st.node == target_stmt {
                            let first = cur_free_at.unwrap_or(free_pos);
                            return Some(vec![
                                format!("free@{}", loc_str(file, first)),
                                format!("free@{}", loc_str(file, free_pos)),
                            ]);
                        }
                    }
                }
            }

            // Use events.
            if goal == StateGoal::UseAfterFree && st.node == target_stmt && freed == FreedState::Freed {
                if stmt_has_use(stmt, &file.source, &varset) {
                    let first = cur_free_at?;
                    return Some(vec![
                        format!("free@{}", loc_str(file, first)),
                        format!("use@{}", loc_str(file, node.start)),
                    ]);
                }
            }

            for e in &cfg.edges[st.node] {
                let mut ncons = cons.clone();
                if !ncons.apply_all(&e.constraints) {
                    if std::env::var("SAST_VALIDATOR_DEBUG").ok().as_deref() == Some("1") {
                        eprintln!(
                            "[validator] prune: contradictory constraints at {} -> {}",
                            st.node, e.to
                        );
                    }
                    continue;
                }
                let ns = St {
                    node: e.to,
                    freed,
                    constraints: ncons,
                };
                if seen.insert(ns.clone()) {
                    q.push_back(ns.clone());
                    free_at.insert(ns, cur_free_at);
                }
            }
        }
        None
    }

    fn dominance_state_validate(
        &self,
        func_id: &str,
        cfg: &Cfg,
        file: &AstFile,
        vars: &[String],
        target_stmt: usize,
        goal: StateGoal,
    ) -> Option<Vec<String>> {
        let dom = self.dominators(func_id)?;
        let varset: HashSet<String> = vars.iter().cloned().collect();

        let mut free_nodes: Vec<(usize, usize)> = Vec::new(); // (node idx, free_pos byte)
        let mut alloc_nodes: Vec<usize> = Vec::new();
        for (i, n) in cfg.nodes.iter().enumerate() {
            let stmt = node_for_range(file, n.start, n.end)?;
            if stmt_has_alloc_reset(stmt, &file.source, &varset) {
                alloc_nodes.push(i);
            }
            if let Some(fp) = stmt_free_pos(stmt, &file.source, &varset) {
                free_nodes.push((i, fp));
            }
        }

        match goal {
            StateGoal::UseAfterFree => {
                // Find a free node that dominates the use node, and no must-reset between.
                for (fnode, fpos) in &free_nodes {
                    if !dom[target_stmt].contains(*fnode) {
                        continue;
                    }
                    // If a reset node is guaranteed between free and use, don't call it guaranteed.
                    let mut must_reset = false;
                    for r in &alloc_nodes {
                        if dom[*r].contains(*fnode) && dom[target_stmt].contains(*r) {
                            must_reset = true;
                            break;
                        }
                    }
                    if must_reset {
                        continue;
                    }

                    if std::env::var("SAST_VALIDATOR_DEBUG").ok().as_deref() == Some("1") {
                        eprintln!(
                            "[validator] dominance UAF: free node {} dominates use node {}",
                            fnode, target_stmt
                        );
                    }

                    return Some(vec![
                        format!("free@{}", loc_str(file, *fpos)),
                        format!("use@{}", loc_str(file, cfg.nodes[target_stmt].start)),
                    ]);
                }
                None
            }
            StateGoal::DoubleFree => {
                // Second free site is target_stmt; require a prior free that dominates it and no must-reset between.
                let target_free_pos = {
                    let stmt = node_for_range(file, cfg.nodes[target_stmt].start, cfg.nodes[target_stmt].end)?;
                    stmt_free_pos(stmt, &file.source, &varset)?
                };

                for (fnode, fpos) in &free_nodes {
                    if *fnode == target_stmt {
                        continue;
                    }
                    if !dom[target_stmt].contains(*fnode) {
                        continue;
                    }
                    let mut must_reset = false;
                    for r in &alloc_nodes {
                        if dom[*r].contains(*fnode) && dom[target_stmt].contains(*r) {
                            must_reset = true;
                            break;
                        }
                    }
                    if must_reset {
                        continue;
                    }

                    if std::env::var("SAST_VALIDATOR_DEBUG").ok().as_deref() == Some("1") {
                        eprintln!(
                            "[validator] dominance DF: free node {} dominates second free node {}",
                            fnode, target_stmt
                        );
                    }

                    return Some(vec![
                        format!("free@{}", loc_str(file, *fpos)),
                        format!("free@{}", loc_str(file, target_free_pos)),
                    ]);
                }
                None
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StateGoal {
    UseAfterFree,
    DoubleFree,
}

struct StateValidation {
    confidence: Confidence,
    path: Vec<String>,
    notes: Vec<String>,
}

fn contains_pointer_arithmetic(node: Node, source: &str) -> bool {
    // Best-effort: detect `a + b`, `a - b`, `buf + sz`, etc.
    if matches!(node.kind(), "binary_expression" | "additive_expression") {
        let txt = text(source, node);
        if txt.contains('+') || txt.contains('-') {
            return true;
        }
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if contains_pointer_arithmetic(child, source) {
            return true;
        }
    }
    false
}

pub fn validate_findings(mut findings: Vec<Finding>, ast_map: &AstMap, call_graph: &CallGraph) -> Vec<Finding> {
    // NOTE: call_graph currently unused; we validate by reconstructing concrete dataflow from ASTs.
    let _ = call_graph;

    let mut index = ProgramIndex::new(ast_map);
    index.build();

    let mut out = Vec::with_capacity(findings.len());
    for mut finding in findings.drain(..) {
        let mut notes: Vec<String> = Vec::new();

        // Default: heuristic-only MEDIUM unless we can prove a concrete path.
        let mut confidence = Confidence::Medium;
        finding.validated = false;
        finding.validated_path = None;

        // Memory findings: validate ordering intraprocedurally (alloc/free/use order is checked elsewhere).
        if finding.rule_id == "c.double_free" {
            if let Some(v) = index.validate_double_free_state(&finding) {
                finding.validated_path = Some(v.path);
                finding.validated = true;
                confidence = v.confidence;
                notes.push("validated_double_free_state".to_string());
                notes.extend(v.notes);
            } else {
                notes.push("could_not_validate_double_free_ordering".to_string());
            }
        } else if finding.rule_id == "c.use_after_free" {
            if let Some(v) = index.validate_uaf_state(&finding) {
                finding.validated_path = Some(v.path);
                finding.validated = true;
                confidence = v.confidence;
                notes.push("validated_use_after_free_state".to_string());
                notes.extend(v.notes);
            } else {
                notes.push("could_not_validate_uaf_ordering".to_string());
            }
        } else if finding.tainted {
            // Taint findings: attempt true interprocedural path validation.
            if let Some((path, path_notes)) = index.validate_taint_path(&finding) {
                finding.validated_path = Some(path);
                finding.validated = true;
                confidence = Confidence::High;
                notes.extend(path_notes);
            } else {
                // Fallback: do NOT mark LOW automatically; keep MEDIUM.
                notes.push("no_concrete_source_to_sink_path_found".to_string());
            }
        } else {
            // Structural validation for non-taint findings in systems code.
            if let Some((c, p, n)) = index.validate_structural(&finding) {
                confidence = c;
                finding.validated = true;
                finding.validated_path = p;
                notes.extend(n);
            } else {
                notes.push("non_tainted_finding_not_validated".to_string());
            }
        }

        // Strong guard / overwrite can reduce confidence to LOW even if we otherwise couldn't validate.
        if finding.guarded {
            notes.push("guard_detected".to_string());
            finding.severity = downgrade_severity(finding.severity);
            if confidence == Confidence::High && finding.validated_path.is_none() {
                confidence = Confidence::Medium;
            }
        }

        // If validated_path exists, ensure we mark validated.
        if finding.validated_path.is_some() {
            finding.validated = true;
            notes.push("validated_path_reconstructed".to_string());
        }

        // Invariant: HIGH confidence only when validated=true.
        if confidence == Confidence::High && !finding.validated {
            confidence = Confidence::Medium;
        }

        finding.confidence = Some(confidence);
        finding.validation_notes = Some(notes);
        out.push(finding);
    }

    out
}

fn downgrade_severity(sev: Severity) -> Severity {
    match sev {
        Severity::Critical => Severity::High,
        Severity::High => Severity::Medium,
        Severity::Medium => Severity::Low,
        Severity::Low => Severity::Low,
    }
}

fn downgrade_confidence(c: Confidence) -> Confidence {
    match c {
        Confidence::High => Confidence::Medium,
        Confidence::Medium => Confidence::Low,
        Confidence::Low => Confidence::Low,
    }
}

fn function_params(source: &str, fn_node: Node) -> Vec<String> {
    // Best-effort: collect identifiers from parameter_list.
    let mut out = Vec::new();
    let mut stack = Vec::new();
    stack.push(fn_node);
    while let Some(n) = stack.pop() {
        if n.kind() == "parameter_declaration" {
            // Find first identifier under this parameter.
            if let Some(id) = find_first_ident(source, n) {
                out.push(id);
            }
        }
        let mut cursor = n.walk();
        for child in n.named_children(&mut cursor) {
            stack.push(child);
        }
    }
    out
}

fn find_first_ident(source: &str, node: Node) -> Option<String> {
    if node.kind() == "identifier" {
        return Some(text(source, node).to_string());
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if let Some(s) = find_first_ident(source, child) {
            return Some(s);
        }
    }
    None
}

fn callsite_info(source: &str, call: Node) -> Option<(String, Vec<(usize, usize)>)> {
    let callee = call.child_by_field_name("function")?;
    if callee.kind() != "identifier" {
        return None;
    }
    let name = text(source, callee).to_string();
    let args = call.child_by_field_name("arguments")?;
    let mut out = Vec::new();
    let mut cursor = args.walk();
    for a in args.named_children(&mut cursor) {
        out.push((a.start_byte(), a.end_byte()));
    }
    Some((name, out))
}

fn var_key(source: &str, node: Node) -> Option<String> {
    match node.kind() {
        "identifier" => Some(text(source, node).to_string()),
        "field_expression" => {
            let arg = node.child_by_field_name("argument").or_else(|| node.child_by_field_name("left"));
            let field = node.child_by_field_name("field").or_else(|| node.child_by_field_name("right"));
            let (Some(arg), Some(field)) = (arg, field) else { return None };
            if arg.kind() == "identifier" && field.kind() == "field_identifier" {
                Some(format!("{}.{}", text(source, arg), text(source, field)))
            } else {
                None
            }
        }
        _ => None,
    }
}

fn latest_def<'a>(assigns: &'a [Assign], lhs: &str, before: usize) -> Option<&'a Assign> {
    assigns
        .iter()
        .rev()
        .find(|a| a.pos < before && a.lhs == lhs)
}

fn node_for_range<'a>(file: &'a AstFile, start: usize, end: usize) -> Option<Node<'a>> {
    let root = file.tree.root_node();
    let mut n = node_at_byte(root, start)?;
    while n.end_byte() < end {
        n = n.parent()?;
    }
    Some(n)
}

fn loc_str(file: &AstFile, byte: usize) -> String {
    let root = file.tree.root_node();
    let n = node_at_byte(root, byte).unwrap_or(root);
    format!(
        "{}:{}:{}",
        file.path,
        n.start_position().row + 1,
        n.start_position().column + 1
    )
}

fn expr_atoms(file: &AstFile, finfo: &FuncInfo, node: Node) -> Vec<Atom> {
    // Known sources.
    if node.kind() == "subscript_expression" {
        let base = node.child_by_field_name("argument").or_else(|| node.child_by_field_name("left"));
        if base.is_some_and(|b| b.kind() == "identifier" && text(&file.source, b) == "argv") {
            return vec![Atom::Source {
                kind: "argv".to_string(),
                file: file.path.clone(),
                line: node.start_position().row + 1,
                col: node.start_position().column + 1,
            }];
        }
    }
    if node.kind() == "call_expression" {
        if let Some((callee, _args)) = callsite_info(&file.source, node) {
            if matches!(callee.as_str(), "getenv" | "read" | "recv" | "scanf") {
                return vec![Atom::Source {
                    kind: callee,
                    file: file.path.clone(),
                    line: node.start_position().row + 1,
                    col: node.start_position().column + 1,
                }];
            }
            return vec![Atom::Ret(callee)];
        }
    }
    if let Some(v) = var_key(&file.source, node) {
        if let Some(idx) = finfo.param_names.iter().position(|p| p == &v) {
            return vec![Atom::Param(idx)];
        }
        return vec![Atom::Var(v)];
    }

    // Otherwise: collect atoms from children.
    let mut out = Vec::new();
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        out.extend(expr_atoms(file, finfo, child));
    }
    out
}

fn stmt_free_pos(stmt: Node, source: &str, vars: &HashSet<String>) -> Option<usize> {
    let mut stack = vec![stmt];
    while let Some(n) = stack.pop() {
        if n.kind() == "call_expression" {
            if let Some((callee, args)) = callsite_info(source, n) {
                if callee == "free" {
                    if let Some((s, e)) = args.get(0).copied() {
                        let arg_node = find_node_span(stmt, s, e);
                        if let Some(arg_node) = arg_node {
                            if let Some(v) = var_key(source, arg_node) {
                                if vars.contains(&v) {
                                    return Some(n.start_byte());
                                }
                            }
                        }
                    }
                }
            }
        }
        let mut cursor = n.walk();
        for ch in n.named_children(&mut cursor) {
            stack.push(ch);
        }
    }
    None
}

fn stmt_has_alloc_reset(stmt: Node, source: &str, vars: &HashSet<String>) -> bool {
    let mut stack = vec![stmt];
    while let Some(n) = stack.pop() {
        if n.kind() == "assignment_expression" {
            let left = n.child_by_field_name("left");
            let right = n.child_by_field_name("right");
            if let (Some(l), Some(r)) = (left, right) {
                if let Some(lhs) = var_key(source, l) {
                    if vars.contains(&lhs) && is_alloc_or_clear_expr(source, r) {
                        return true;
                    }
                }
            }
        }
        if n.kind() == "init_declarator" {
            let decl = n.child_by_field_name("declarator");
            let val = n.child_by_field_name("value");
            if let (Some(decl), Some(val)) = (decl, val) {
                if let Some(lhs) = find_first_ident(source, decl) {
                    if vars.contains(&lhs) && is_alloc_or_clear_expr(source, val) {
                        return true;
                    }
                }
            }
        }
        let mut cursor = n.walk();
        for ch in n.named_children(&mut cursor) {
            stack.push(ch);
        }
    }
    false
}

fn stmt_has_use(stmt: Node, source: &str, vars: &HashSet<String>) -> bool {
    let mut stack = vec![stmt];
    while let Some(n) = stack.pop() {
        match n.kind() {
            "unary_expression" => {
                let txt = text(source, n);
                if txt.trim_start().starts_with('*') {
                    if let Some(arg) = n.named_child(0) {
                        if let Some(v) = var_key(source, arg) {
                            if vars.contains(&v) {
                                return true;
                            }
                        }
                    }
                }
            }
            "subscript_expression" => {
                let base = n.child_by_field_name("argument").or_else(|| n.child_by_field_name("left"));
                if let Some(base) = base {
                    if let Some(v) = var_key(source, base) {
                        if vars.contains(&v) {
                            return true;
                        }
                    }
                }
            }
            "field_expression" => {
                if let Some(v) = var_key(source, n) {
                    if vars.contains(&v) {
                        return true;
                    }
                }
            }
            "call_expression" => {
                if let Some((callee, args)) = callsite_info(source, n) {
                    if callee != "free" {
                        for (s, e) in args {
                            if let Some(argn) = find_node_span(stmt, s, e) {
                                if let Some(v) = var_key(source, argn) {
                                    if vars.contains(&v) {
                                        return true;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            _ => {}
        }
        let mut cursor = n.walk();
        for ch in n.named_children(&mut cursor) {
            stack.push(ch);
        }
    }
    false
}

fn is_alloc_or_clear_expr(source: &str, node: Node) -> bool {
    let mut n = node;
    loop {
        match n.kind() {
            "parenthesized_expression" | "cast_expression" => {
                if let Some(inner) = n.named_child(0) {
                    n = inner;
                    continue;
                }
            }
            _ => {}
        }
        break;
    }

    match n.kind() {
        "call_expression" => {
            if let Some((callee, _)) = callsite_info(source, n) {
                matches!(callee.as_str(), "malloc" | "calloc" | "realloc")
            } else {
                false
            }
        }
        "number_literal" => text(source, n).trim() == "0",
        "identifier" => text(source, n).trim() == "NULL",
        _ => false,
    }
}

fn find_node_span<'a>(root: Node<'a>, start: usize, end: usize) -> Option<Node<'a>> {
    // Find a node spanning [start,end) under root.
    if start < root.start_byte() || end > root.end_byte() {
        return None;
    }
    let mut cur = root;
    loop {
        let mut found = None;
        let mut cursor = cur.walk();
        for ch in cur.named_children(&mut cursor) {
            if start >= ch.start_byte() && end <= ch.end_byte() {
                found = Some(ch);
                break;
            }
        }
        match found {
            Some(n) => cur = n,
            None => return Some(cur),
        }
    }
}

fn condition_constraints(source: &str, cond: Node) -> (Vec<Constraint>, Vec<Constraint>) {
    // Return (then_constraints, else_constraints)
    // Supported:
    // - `if (flag)` / `if (!flag)`
    // - `if (p != NULL)` / `if (p == NULL)` and `0`
    // - basic `&&` combinations on then-branch.
    match cond.kind() {
        "identifier" => {
            let name = text(source, cond).to_string();
            (
                vec![Constraint::VarEq { name: name.clone(), value: true }],
                vec![Constraint::VarEq { name, value: false }],
            )
        }
        "unary_expression" => {
            let txt = text(source, cond).trim().to_string();
            if txt.starts_with('!') {
                if let Some(arg) = cond.named_child(0) {
                    if arg.kind() == "identifier" {
                        let name = text(source, arg).to_string();
                        return (
                            vec![Constraint::VarEq { name: name.clone(), value: false }],
                            vec![Constraint::VarEq { name, value: true }],
                        );
                    }
                }
            }
            (Vec::new(), Vec::new())
        }
        "binary_expression" => {
            // operator is typically child(1)
            let op = cond.child(1).map(|c| text(source, c)).unwrap_or("");
            let left = cond.child(0);
            let right = cond.child(2);

            if op == "&&" {
                // then: combine; else: unknown
                if let (Some(l), Some(r)) = (left, right) {
                    let (mut lt, _le) = condition_constraints(source, l);
                    let (rt, _re) = condition_constraints(source, r);
                    lt.extend(rt);
                    return (lt, Vec::new());
                }
            }

            if let (Some(l), Some(r)) = (left, right) {
                if l.kind() == "identifier" {
                    let name = text(source, l).to_string();
                    let rtxt = text(source, r).trim();
                    let is_null = r.kind() == "identifier" && rtxt == "NULL" || r.kind() == "number_literal" && rtxt == "0";
                    if is_null {
                        return match op {
                            "!=" => (
                                vec![Constraint::PtrNonNull { name: name.clone() }],
                                vec![Constraint::PtrNull { name }],
                            ),
                            "==" => (
                                vec![Constraint::PtrNull { name: name.clone() }],
                                vec![Constraint::PtrNonNull { name }],
                            ),
                            _ => (Vec::new(), Vec::new()),
                        };
                    }
                }
            }
            (Vec::new(), Vec::new())
        }
        _ => (Vec::new(), Vec::new()),
    }
}

fn line_starts(source: &str) -> Vec<usize> {
    let mut starts = vec![0usize];
    for (i, b) in source.as_bytes().iter().enumerate() {
        if *b == b'\n' {
            starts.push(i + 1);
        }
    }
    starts
}

fn offset_for(file: &AstFile, line: usize, column: usize) -> Option<usize> {
    if line == 0 {
        return None;
    }
    let idx = line - 1;
    let start = *file.line_starts.get(idx)?;
    Some(start + column.saturating_sub(1))
}

fn node_at_byte<'a>(root: Node<'a>, byte: usize) -> Option<Node<'a>> {
    if byte < root.start_byte() || byte >= root.end_byte() {
        return None;
    }
    let mut cur = root;
    loop {
        let mut found = None;
        let mut cursor = cur.walk();
        for child in cur.named_children(&mut cursor) {
            if byte >= child.start_byte() && byte < child.end_byte() {
                found = Some(child);
                break;
            }
        }
        match found {
            Some(n) => cur = n,
            None => return Some(cur),
        }
    }
}

fn ancestor_of_kind<'a>(mut node: Node<'a>, kind: &str) -> Option<Node<'a>> {
    loop {
        if node.kind() == kind {
            return Some(node);
        }
        node = node.parent()?;
    }
}

fn text<'a>(source: &'a str, node: Node<'_>) -> &'a str {
    &source[node.start_byte()..node.end_byte()]
}

fn fn_id(path: &str, name: &str) -> String {
    format!("{path}::{name}")
}

fn function_name_and_body<'a>(source: &str, fn_node: Node<'a>) -> Option<(String, Node<'a>)> {
    let declarator = fn_node.child_by_field_name("declarator")?;
    let body = fn_node.child_by_field_name("body")?;
    // Find the first identifier in the declarator (deep).
    fn find_ident<'b>(source: &str, node: Node<'b>) -> Option<String> {
        if node.kind() == "identifier" {
            return Some(text(source, node).to_string());
        }
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            if let Some(s) = find_ident(source, child) {
                return Some(s);
            }
        }
        None
    }

    let name = find_ident(source, declarator)?;
    Some((name, body))
}

fn collect_calls<'a, F: FnMut(String)>(source: &str, node: Node<'a>, on_call: &mut F) {
    let mut stack = vec![node];
    while let Some(n) = stack.pop() {
        if n.kind() == "call_expression" {
            if let Some(func) = n.child_by_field_name("function") {
                if func.kind() == "identifier" {
                    on_call(text(source, func).to_string());
                }
            }
        }
        let mut cursor = n.walk();
        for child in n.named_children(&mut cursor) {
            stack.push(child);
        }
    }
}

fn find_containing_function(file: &AstFile, byte: usize) -> Option<String> {
    let root = file.tree.root_node();
    let node = node_at_byte(root, byte)?;
    let func = ancestor_of_kind(node, "function_definition")?;
    function_name_and_body(&file.source, func).map(|(n, _)| n)
}

fn value_overridden_by_constant(finding: &Finding, file: &AstFile) -> bool {
    let Some(src_loc) = finding.source_location.as_ref() else { return false };
    let Some(src_off) = offset_for(file, src_loc.line, src_loc.column) else { return false };
    let Some(sink_off) = offset_for(file, finding.location.line, finding.location.column) else { return false };
    if sink_off <= src_off {
        return false;
    }

    let Some(vctx) = finding.vuln_context.as_ref() else { return false };
    let Some(arg_positions) = vctx.arg_positions.as_ref() else { return false };

    let root = file.tree.root_node();
    let Some(node) = node_at_byte(root, sink_off) else { return false };
    let Some(call) = ancestor_of_kind(node, "call_expression") else { return false };
    let Some(args) = call.child_by_field_name("arguments") else { return false };

    let mut tainted_vars = BTreeSet::new();
    for &pos in arg_positions {
        if let Some(arg) = args.named_child(pos) {
            if arg.kind() == "identifier" {
                tainted_vars.insert(text(&file.source, arg).to_string());
            }
        }
    }
    if tainted_vars.is_empty() {
        return false;
    }

    // Search for `x = <literal>` assignments between source and sink within the containing function.
    let Some(func) = find_containing_function_node(file, sink_off) else { return false };
    let mut stack = vec![func];
    while let Some(n) = stack.pop() {
        if n.kind() == "assignment_expression" {
            let left = n.child_by_field_name("left");
            let right = n.child_by_field_name("right");
            if let (Some(l), Some(r)) = (left, right) {
                if l.kind() == "identifier" && is_literal(r) {
                    let name = text(&file.source, l).to_string();
                    if tainted_vars.contains(&name) {
                        let off = n.start_byte();
                        if off > src_off && off < sink_off {
                            return true;
                        }
                    }
                }
            }
        }
        let mut cursor = n.walk();
        for child in n.named_children(&mut cursor) {
            stack.push(child);
        }
    }
    false
}

fn find_containing_function_node<'a>(file: &'a AstFile, byte: usize) -> Option<Node<'a>> {
    let root = file.tree.root_node();
    let node = node_at_byte(root, byte)?;
    ancestor_of_kind(node, "function_definition")
}

fn is_literal(node: Node) -> bool {
    matches!(
        node.kind(),
        "string_literal" | "number_literal" | "char_literal" | "true" | "false"
    )
}

fn validate_double_free(finding: &Finding, file: &AstFile) -> Result<(), String> {
    let sink_off = offset_for(file, finding.location.line, finding.location.column).ok_or("bad_location")?;
    let root = file.tree.root_node();
    let node = node_at_byte(root, sink_off).ok_or("no_node_at_location")?;
    let call = ancestor_of_kind(node, "call_expression").ok_or("no_call_expression")?;
    let func = call.child_by_field_name("function").ok_or("no_callee")?;
    if text(&file.source, func) != "free" {
        return Err("not_a_free_call".to_string());
    }
    let args = call
        .child_by_field_name("arguments")
        .ok_or_else(|| "no_arguments".to_string())?;
    let arg0 = args
        .named_child(0)
        .ok_or_else(|| "no_free_arg".to_string())?;
    if arg0.kind() != "identifier" {
        return Err("free_arg_not_identifier".to_string());
    }
    let name = text(&file.source, arg0).to_string();

    let func_node = find_containing_function_node(file, sink_off).ok_or("no_containing_function")?;
    let mut frees = Vec::new();

    let mut stack = vec![func_node];
    while let Some(n) = stack.pop() {
        if n.kind() == "call_expression" {
            if let Some(callee) = n.child_by_field_name("function") {
                if callee.kind() == "identifier" && text(&file.source, callee) == "free" {
                    if let Some(arg0) = n.child_by_field_name("arguments").and_then(|a| a.named_child(0)) {
                        if arg0.kind() == "identifier" && text(&file.source, arg0) == name {
                            frees.push(n.start_byte());
                        }
                    }
                }
            }
        }
        let mut cursor = n.walk();
        for child in n.named_children(&mut cursor) {
            stack.push(child);
        }
    }
    frees.sort();
    let idx = frees.iter().position(|&b| b == call.start_byte()).ok_or("free_call_not_found")?;
    if idx == 0 {
        return Err("free_sequence_not_confirmed".to_string());
    }
    Ok(())
}

fn validate_uaf(finding: &Finding, file: &AstFile) -> Result<(), String> {
    let sink_off = offset_for(file, finding.location.line, finding.location.column).ok_or("bad_location")?;
    let root = file.tree.root_node();
    let node = node_at_byte(root, sink_off).ok_or("no_node_at_location")?;
    // Try to find an identifier at the finding site.
    let mut cur = node;
    let mut id: Option<String> = None;
    loop {
        if cur.kind() == "identifier" {
            id = Some(text(&file.source, cur).to_string());
            break;
        }
        cur = match cur.parent() {
            Some(p) => p,
            None => break,
        };
    }
    let Some(id) = id else { return Err("no_identifier_at_use_site".to_string()) };

    let func_node = find_containing_function_node(file, sink_off).ok_or("no_containing_function")?;
    let mut saw_free = false;
    let mut stack = vec![func_node];
    while let Some(n) = stack.pop() {
        if n.start_byte() >= sink_off {
            // Only consider nodes before the use site.
        } else if n.kind() == "call_expression" {
            if let Some(callee) = n.child_by_field_name("function") {
                if callee.kind() == "identifier" && text(&file.source, callee) == "free" {
                    if let Some(arg0) = n.child_by_field_name("arguments").and_then(|a| a.named_child(0)) {
                        if arg0.kind() == "identifier" && text(&file.source, arg0) == id {
                            saw_free = true;
                        }
                    }
                }
            }
        }
        let mut cursor = n.walk();
        for child in n.named_children(&mut cursor) {
            stack.push(child);
        }
    }
    if !saw_free {
        return Err("no_prior_free_found".to_string());
    }
    Ok(())
}
