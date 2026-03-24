#![allow(dead_code)]

use std::collections::BTreeMap;

use tree_sitter::Node;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EdgeKind {
    Next,
    True,
    False,
    Back,
}

#[derive(Debug, Clone)]
pub(crate) struct CfgNode {
    pub(crate) id: usize,
    pub(crate) kind: String,
    pub(crate) start_byte: usize,
    pub(crate) end_byte: usize,
    pub(crate) conditional: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct CfgEdge {
    pub(crate) from: usize,
    pub(crate) to: usize,
    pub(crate) kind: EdgeKind,
    pub(crate) conditional: bool,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct Cfg {
    pub(crate) nodes: Vec<CfgNode>,
    pub(crate) edges: Vec<CfgEdge>,
    pub(crate) entry: Option<usize>,
}

impl Cfg {
    fn add_node(&mut self, node: Node, conditional: bool) -> usize {
        let id = self.nodes.len();
        self.nodes.push(CfgNode {
            id,
            kind: node.kind().to_string(),
            start_byte: node.start_byte(),
            end_byte: node.end_byte(),
            conditional,
        });
        if self.entry.is_none() {
            self.entry = Some(id);
        }
        id
    }

    fn add_edge(&mut self, from: usize, to: usize, kind: EdgeKind, conditional: bool) {
        self.edges.push(CfgEdge {
            from,
            to,
            kind,
            conditional,
        });
    }
}

/// Very small CFG builder:
/// - Nodes are statement-level AST nodes.
/// - Edges approximate structured control flow for if/else and loops.
/// - Each node is marked `conditional` when it is in a conditional/loop body.
pub(crate) fn build_cfg_for_function(body: Node) -> Cfg {
    let mut cfg = Cfg::default();
    let mut b = Builder { cfg: &mut cfg };
    let _ = b.build_stmt(body, false, None);
    cfg
}

struct Builder<'a> {
    cfg: &'a mut Cfg,
}

impl<'a> Builder<'a> {
    /// Returns (entry, exits)
    fn build_stmt(&mut self, node: Node, conditional: bool, next: Option<usize>) -> (Option<usize>, Vec<usize>) {
        match node.kind() {
            "compound_statement" | "translation_unit" => self.build_block(node, conditional, next),
            "if_statement" => self.build_if(node, conditional, next),
            "for_statement" | "while_statement" | "do_statement" => self.build_loop(node, conditional, next),
            _ => self.build_simple(node, conditional, next),
        }
    }

    fn build_block(&mut self, node: Node, conditional: bool, next: Option<usize>) -> (Option<usize>, Vec<usize>) {
        let mut stmts: Vec<Node> = Vec::new();
        let mut cursor = node.walk();
        for child in node.named_children(&mut cursor) {
            stmts.push(child);
        }
        self.build_seq(&stmts, conditional, next)
    }

    fn build_seq(
        &mut self,
        stmts: &[Node],
        conditional: bool,
        next: Option<usize>,
    ) -> (Option<usize>, Vec<usize>) {
        if stmts.is_empty() {
            return (next, next.into_iter().collect());
        }

        // Build backwards so we can thread `next` through.
        let mut cur_next = next;
        let mut entry: Option<usize> = None;
        let mut exits: Vec<usize> = Vec::new();
        for s in stmts.iter().rev() {
            let (e, xs) = self.build_stmt(*s, conditional, cur_next);
            if entry.is_none() {
                exits = xs;
            }
            entry = e;
            cur_next = e;
        }
        (entry, exits)
    }

    fn build_simple(&mut self, node: Node, conditional: bool, next: Option<usize>) -> (Option<usize>, Vec<usize>) {
        let id = self.cfg.add_node(node, conditional);
        if let Some(n) = next {
            self.cfg.add_edge(id, n, EdgeKind::Next, false);
            (Some(id), vec![n])
        } else {
            (Some(id), vec![id])
        }
    }

    fn build_if(&mut self, node: Node, conditional: bool, next: Option<usize>) -> (Option<usize>, Vec<usize>) {
        let if_id = self.cfg.add_node(node, conditional);
        let cons = node.child_by_field_name("consequence");
        let alt = node.child_by_field_name("alternative");

        let (then_entry, then_exits) = cons
            .map(|c| self.build_stmt(c, true, next))
            .unwrap_or((next, next.into_iter().collect()));
        let (else_entry, else_exits) = alt
            .map(|c| self.build_stmt(c, true, next))
            .unwrap_or((next, next.into_iter().collect()));

        if let Some(t) = then_entry {
            self.cfg.add_edge(if_id, t, EdgeKind::True, true);
        } else if let Some(n) = next {
            self.cfg.add_edge(if_id, n, EdgeKind::True, false);
        }

        if let Some(e) = else_entry {
            self.cfg.add_edge(if_id, e, EdgeKind::False, true);
        } else if let Some(n) = next {
            self.cfg.add_edge(if_id, n, EdgeKind::False, false);
        }

        // Merge: connect all branch exits to `next` if present.
        if let Some(n) = next {
            for x in then_exits.iter().chain(else_exits.iter()) {
                self.cfg.add_edge(*x, n, EdgeKind::Next, false);
            }
            (Some(if_id), vec![n])
        } else {
            let mut exits = Vec::new();
            exits.extend(then_exits);
            exits.extend(else_exits);
            (Some(if_id), exits)
        }
    }

    fn build_loop(&mut self, node: Node, conditional: bool, next: Option<usize>) -> (Option<usize>, Vec<usize>) {
        let head_id = self.cfg.add_node(node, conditional);
        let body = node.child_by_field_name("body").or_else(|| node.child_by_field_name("statement"));

        let (body_entry, body_exits) = body
            .map(|b| self.build_stmt(b, true, Some(head_id)))
            .unwrap_or((Some(head_id), vec![head_id]));

        if let Some(be) = body_entry {
            self.cfg.add_edge(head_id, be, EdgeKind::True, true);
        }
        if let Some(n) = next {
            self.cfg.add_edge(head_id, n, EdgeKind::False, false);
            (Some(head_id), vec![n])
        } else {
            (Some(head_id), body_exits)
        }
    }
}

/// Optional helper for future usage: maps statement span to whether it is conditional.
pub(crate) fn conditional_map(cfg: &Cfg) -> BTreeMap<(usize, usize), bool> {
    let mut m = BTreeMap::new();
    for n in &cfg.nodes {
        m.insert((n.start_byte, n.end_byte), n.conditional);
    }
    m
}
