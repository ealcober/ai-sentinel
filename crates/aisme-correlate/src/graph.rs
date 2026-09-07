// SPDX-License-Identifier: Apache-2.0
//! The causal graph, with Annex A.3's invariants as code (`F1.ON.02`).
//!
//! Three invariants, checked on every insertion and again by [`Graph::validate`]:
//!
//! - **Endpoints follow A.2.** An edge whose ends are not the kinds its row
//!   names is refused (`EdgeKind::endpoints`, the annex as data).
//! - **The graph is a DAG.** An edge that would close a cycle is refused and
//!   counted; a cycle is a correlation bug, never a fact about the session.
//! - **Every `Process` has exactly one `executed_as` parent, or is explicitly
//!   `orphan`.** A process cannot be added without saying which; a second
//!   parent is refused; orphans are counted as `aisme.correlation.unmatched`,
//!   the detection-quality signal.
//!
//! Refusals are returned *and* counted, so a release build keeps the numbers
//! and a debug build can `debug_assert!` on them at the points it chooses.
//! Everything the graph will own is allocated in [`Graph::with_capacity`]:
//! adjacency is linked through preallocated arrays and the cycle search uses
//! an epoch-marked visited table, so steady state allocates nothing
//! (`F1.RT.03`) and a full graph refuses rather than grows (`F1.RT.04`).

use aisme_core::ontology::{Edge, EdgeKind, Node, NodeId, NodeKind};

const NONE: u32 = u32::MAX;

/// Why an insertion was refused. Each variant is also a counter in
/// [`GraphStats`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GraphError {
    /// The graph holds as many nodes or edges as it was built for.
    Full,
    /// An id this graph never issued.
    UnknownNode(NodeId),
    /// The ends are not the kinds A.2 names for this edge.
    Endpoints {
        /// The edge.
        kind: EdgeKind,
        /// What sat at the source.
        from: NodeKind,
        /// What sat at the target.
        to: NodeKind,
    },
    /// The edge would close a cycle (or is a self-loop).
    Cycle,
    /// The process already has an `executed_as` parent.
    SecondParent {
        /// The process.
        process: NodeId,
        /// Its existing parent.
        existing: NodeId,
    },
    /// A `Process` node must be added with [`Graph::add_process`], saying
    /// whether it is attributed or an orphan.
    ProcessNeedsAttribution,
}

impl core::fmt::Display for GraphError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            GraphError::Full => write!(f, "graph is full"),
            GraphError::UnknownNode(id) => write!(f, "unknown node {id:?}"),
            GraphError::Endpoints { kind, from, to } => {
                write!(
                    f,
                    "{kind:?} may not run from {from:?} to {to:?} (Annex A.2)"
                )
            }
            GraphError::Cycle => write!(f, "edge would close a cycle (Annex A.3)"),
            GraphError::SecondParent { process, existing } => write!(
                f,
                "{process:?} already has executed_as parent {existing:?} (Annex A.3)"
            ),
            GraphError::ProcessNeedsAttribution => {
                write!(
                    f,
                    "a Process is added with add_process, attributed or orphan"
                )
            }
        }
    }
}

impl core::error::Error for GraphError {}

/// How a `Process` relates to the tool call that caused it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Attribution {
    /// `executed_as` this `ToolCall`.
    ExecutedAs(NodeId),
    /// Unattributed, and said so: counted as `aisme.correlation.unmatched`.
    Orphan,
}

/// What the graph holds and what it refused (`F1.RT.06` feeds these out).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GraphStats {
    /// Nodes held.
    pub nodes: usize,
    /// Edges held.
    pub edges: usize,
    /// `Process` nodes added as orphans — `aisme.correlation.unmatched`.
    pub unmatched: u64,
    /// Insertions refused because the graph was full.
    pub refused_full: u64,
    /// Edges refused for their endpoint kinds.
    pub refused_endpoints: u64,
    /// Edges refused because they would close a cycle.
    pub refused_cycles: u64,
    /// `executed_as` edges refused as a second parent.
    pub refused_second_parent: u64,
}

/// A bounded causal graph for one session.
pub struct Graph {
    nodes: Vec<Node>,
    edges: Vec<Edge>,
    /// Per node: the first outgoing edge, chained through `next_out`.
    first_out: Vec<u32>,
    next_out: Vec<u32>,
    /// Per node: the `executed_as` parent, for `Process` nodes that have one.
    parent: Vec<u32>,
    /// Per node: whether a `Process` was added as an orphan.
    orphan: Vec<bool>,
    /// Cycle search scratch: epoch marks and a stack, allocated once.
    mark: Vec<u32>,
    epoch: u32,
    stack: Vec<u32>,
    stats: GraphStats,
}

impl Graph {
    /// A graph for at most `nodes` nodes and `edges` edges. Everything is
    /// allocated here.
    ///
    /// # Panics
    ///
    /// When either capacity is zero or would not fit the `u32` indices.
    #[must_use]
    pub fn with_capacity(nodes: usize, edges: usize) -> Graph {
        assert!((1..NONE as usize).contains(&nodes), "nodes: 1..=u32::MAX-1");
        assert!((1..NONE as usize).contains(&edges), "edges: 1..=u32::MAX-1");
        Graph {
            nodes: Vec::with_capacity(nodes),
            edges: Vec::with_capacity(edges),
            first_out: Vec::with_capacity(nodes),
            next_out: Vec::with_capacity(edges),
            parent: Vec::with_capacity(nodes),
            orphan: Vec::with_capacity(nodes),
            mark: Vec::with_capacity(nodes),
            epoch: 0,
            stack: Vec::with_capacity(nodes),
            stats: GraphStats::default(),
        }
    }

    /// Add any node but a `Process`, which needs [`Graph::add_process`].
    ///
    /// # Errors
    ///
    /// [`GraphError::Full`], [`GraphError::ProcessNeedsAttribution`].
    pub fn add_node(&mut self, node: Node) -> Result<NodeId, GraphError> {
        if node.kind() == NodeKind::Process {
            return Err(GraphError::ProcessNeedsAttribution);
        }
        self.push_node(node, false)
    }

    /// Add a `Process`, attributed to its tool call or explicitly an orphan.
    /// The `executed_as` edge is added here, under the same checks as
    /// [`Graph::add_edge`].
    ///
    /// # Errors
    ///
    /// [`GraphError::Full`]; for an attribution, whatever the edge refuses —
    /// and then the node is not added either.
    pub fn add_process(
        &mut self,
        node: Node,
        attribution: Attribution,
    ) -> Result<NodeId, GraphError> {
        debug_assert_eq!(node.kind(), NodeKind::Process);
        match attribution {
            Attribution::Orphan => {
                let id = self.push_node(node, true)?;
                self.stats.unmatched += 1;
                Ok(id)
            }
            Attribution::ExecutedAs(tool_call) => {
                // Check what can be checked before the node exists, so a
                // refusal leaves the graph as it was.
                let from_kind = self.kind_of(tool_call)?;
                if !EdgeKind::ExecutedAs.permits(from_kind, NodeKind::Process) {
                    self.stats.refused_endpoints += 1;
                    return Err(GraphError::Endpoints {
                        kind: EdgeKind::ExecutedAs,
                        from: from_kind,
                        to: NodeKind::Process,
                    });
                }
                if self.edges.len() == self.edges.capacity() {
                    self.stats.refused_full += 1;
                    return Err(GraphError::Full);
                }
                let id = self.push_node(node, false)?;
                // A brand-new node has no outgoing edges, so no cycle is
                // possible and no parent exists: the edge goes straight in.
                self.push_edge(Edge {
                    from: tool_call,
                    to: id,
                    kind: EdgeKind::ExecutedAs,
                });
                self.parent[index(id)] = index32(tool_call);
                Ok(id)
            }
        }
    }

    /// Add an edge between two existing nodes.
    ///
    /// # Errors
    ///
    /// Every variant of [`GraphError`] but `ProcessNeedsAttribution`; each
    /// refusal is also counted.
    pub fn add_edge(&mut self, from: NodeId, to: NodeId, kind: EdgeKind) -> Result<(), GraphError> {
        let from_kind = self.kind_of(from)?;
        let to_kind = self.kind_of(to)?;
        if !kind.permits(from_kind, to_kind) {
            self.stats.refused_endpoints += 1;
            return Err(GraphError::Endpoints {
                kind,
                from: from_kind,
                to: to_kind,
            });
        }
        if kind == EdgeKind::ExecutedAs {
            let existing = self.parent[index(to)];
            if existing != NONE {
                self.stats.refused_second_parent += 1;
                return Err(GraphError::SecondParent {
                    process: to,
                    existing: NodeId(u64::from(existing)),
                });
            }
        }
        if from == to || self.reaches(to, from) {
            self.stats.refused_cycles += 1;
            return Err(GraphError::Cycle);
        }
        if self.edges.len() == self.edges.capacity() {
            self.stats.refused_full += 1;
            return Err(GraphError::Full);
        }
        self.push_edge(Edge { from, to, kind });
        if kind == EdgeKind::ExecutedAs {
            self.parent[index(to)] = index32(from);
        }
        Ok(())
    }

    /// The node behind an id.
    #[must_use]
    pub fn node(&self, id: NodeId) -> Option<&Node> {
        self.nodes.get(index(id))
    }

    /// The edges leaving a node, newest first.
    pub fn edges_from(&self, id: NodeId) -> impl Iterator<Item = &Edge> + '_ {
        let mut e = self.first_out.get(index(id)).copied().unwrap_or(NONE);
        core::iter::from_fn(move || {
            if e == NONE {
                return None;
            }
            let edge = &self.edges[e as usize];
            e = self.next_out[e as usize];
            Some(edge)
        })
    }

    /// The `executed_as` parent of a process, if it has one.
    #[must_use]
    pub fn parent_of(&self, id: NodeId) -> Option<NodeId> {
        match self.parent.get(index(id)).copied() {
            Some(p) if p != NONE => Some(NodeId(u64::from(p))),
            _ => None,
        }
    }

    /// Whether a process was added as an orphan.
    #[must_use]
    pub fn is_orphan(&self, id: NodeId) -> bool {
        self.orphan.get(index(id)).copied().unwrap_or(false)
    }

    /// Every edge, in insertion order.
    #[must_use]
    pub fn edges(&self) -> &[Edge] {
        &self.edges
    }

    /// Counts.
    #[must_use]
    pub const fn stats(&self) -> GraphStats {
        self.stats
    }

    /// Re-check every invariant over the whole graph — for a `debug_assert!`
    /// at the points the caller chooses, and for the replay tests.
    ///
    /// # Errors
    ///
    /// The first invariant found broken. Insertion already refuses each of
    /// these, so an error here is a bug in this file, not in the caller.
    pub fn validate(&mut self) -> Result<(), GraphError> {
        for (i, node) in self.nodes.iter().enumerate() {
            if node.kind() == NodeKind::Process && self.parent[i] == NONE && !self.orphan[i] {
                return Err(GraphError::ProcessNeedsAttribution);
            }
        }
        for edge in &self.edges {
            let (from, to) = (
                self.nodes[index(edge.from)].kind(),
                self.nodes[index(edge.to)].kind(),
            );
            if !edge.kind.permits(from, to) {
                return Err(GraphError::Endpoints {
                    kind: edge.kind,
                    from,
                    to,
                });
            }
        }
        // A cycle exists iff some edge's target reaches its source.
        for e in 0..self.edges.len() {
            let Edge { from, to, .. } = self.edges[e];
            if from == to || self.reaches(to, from) {
                return Err(GraphError::Cycle);
            }
        }
        Ok(())
    }

    fn kind_of(&self, id: NodeId) -> Result<NodeKind, GraphError> {
        self.nodes
            .get(index(id))
            .map(Node::kind)
            .ok_or(GraphError::UnknownNode(id))
    }

    fn push_node(&mut self, node: Node, orphan: bool) -> Result<NodeId, GraphError> {
        if self.nodes.len() == self.nodes.capacity() {
            self.stats.refused_full += 1;
            return Err(GraphError::Full);
        }
        let id = index32_of(self.nodes.len());
        self.nodes.push(node);
        self.first_out.push(NONE);
        self.parent.push(NONE);
        self.orphan.push(orphan);
        self.mark.push(0);
        self.stats.nodes += 1;
        Ok(NodeId(u64::from(id)))
    }

    fn push_edge(&mut self, edge: Edge) {
        let e = index32_of(self.edges.len());
        let from = index(edge.from);
        self.next_out.push(self.first_out[from]);
        self.first_out[from] = e;
        self.edges.push(edge);
        self.stats.edges += 1;
    }

    /// Whether `target` is reachable from `start` along existing edges —
    /// iterative DFS over the preallocated stack, epoch-marked so nothing is
    /// cleared between searches.
    fn reaches(&mut self, start: NodeId, target: NodeId) -> bool {
        self.epoch = self.epoch.wrapping_add(1);
        if self.epoch == 0 {
            // A wrapped epoch would alias stale marks; reset once per 2^32.
            self.mark.iter_mut().for_each(|m| *m = 0);
            self.epoch = 1;
        }
        let target = index32(target);
        self.stack.clear();
        self.stack.push(index32(start));
        while let Some(n) = self.stack.pop() {
            if n == target {
                return true;
            }
            if self.mark[n as usize] == self.epoch {
                continue;
            }
            self.mark[n as usize] = self.epoch;
            let mut e = self.first_out[n as usize];
            while e != NONE {
                let next = index32(self.edges[e as usize].to);
                if self.mark[next as usize] != self.epoch {
                    self.stack.push(next);
                }
                e = self.next_out[e as usize];
            }
        }
        false
    }
}

impl core::fmt::Debug for Graph {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Graph")
            .field("stats", &self.stats)
            .finish_non_exhaustive()
    }
}

fn index(id: NodeId) -> usize {
    usize::try_from(id.0).unwrap_or(usize::MAX)
}

fn index32(id: NodeId) -> u32 {
    u32::try_from(id.0).unwrap_or(NONE)
}

fn index32_of(len: usize) -> u32 {
    u32::try_from(len).unwrap_or(NONE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aisme_core::intern::StrId;
    use aisme_core::ontology::{BootNs, DeclaredTargets, Digest, PathClass, SessionId};
    use aisme_core::taint::Taint;

    fn prompt() -> Node {
        Node::Prompt {
            session_id: SessionId(1),
            ts: BootNs(1),
            raw_text_hash: Digest([0; 32]),
            token_count: 3,
        }
    }

    fn tool_call(id: u64) -> Node {
        Node::ToolCall {
            tool_name: StrId::from_raw(1),
            params_hash: Digest([0; 32]),
            toolcall_id: id,
            declared_targets: DeclaredTargets::default(),
        }
    }

    fn process(pid: u32) -> Node {
        Node::Process {
            pid,
            tgid: pid,
            ppid: 1,
            exe_path: StrId::from_raw(2),
            argv_hash: 0,
            cgroup: 0,
            taint: Taint::EMPTY,
        }
    }

    fn file() -> Node {
        Node::File {
            inode: 1,
            dev: 1,
            canonical_path: StrId::from_raw(3),
            path_class: PathClass::Unclassified,
            content_hash: None,
            entropy_milli: None,
            size: 0,
            taint: Taint::EMPTY,
        }
    }

    #[test]
    fn a_well_formed_slice_validates() {
        let mut g = Graph::with_capacity(8, 8);
        let p = g.add_node(prompt()).unwrap();
        let tc = g.add_node(tool_call(1)).unwrap();
        g.add_edge(tc, p, EdgeKind::GeneratedBy).unwrap();
        let proc_ = g
            .add_process(process(100), Attribution::ExecutedAs(tc))
            .unwrap();
        let f = g.add_node(file()).unwrap();
        g.add_edge(proc_, f, EdgeKind::Mutated).unwrap();
        assert_eq!(g.parent_of(proc_), Some(tc));
        assert!(!g.is_orphan(proc_));
        assert_eq!(g.validate(), Ok(()));
        assert_eq!(g.stats().nodes, 4);
        assert_eq!(g.stats().edges, 3);
        assert_eq!(g.stats().unmatched, 0);
        let from_tc: Vec<EdgeKind> = g.edges_from(tc).map(|e| e.kind).collect();
        assert_eq!(from_tc, [EdgeKind::ExecutedAs, EdgeKind::GeneratedBy]);
    }

    #[test]
    fn endpoints_outside_a2_are_refused_and_counted() {
        let mut g = Graph::with_capacity(4, 4);
        let p = g.add_node(prompt()).unwrap();
        let f = g.add_node(file()).unwrap();
        let err = g.add_edge(p, f, EdgeKind::Mutated).unwrap_err();
        assert_eq!(
            err,
            GraphError::Endpoints {
                kind: EdgeKind::Mutated,
                from: NodeKind::Prompt,
                to: NodeKind::File
            }
        );
        assert_eq!(g.stats().refused_endpoints, 1);
        assert_eq!(g.stats().edges, 0);
        assert_eq!(g.validate(), Ok(()));
    }

    #[test]
    fn a_cycle_is_refused_where_it_would_close() {
        let mut g = Graph::with_capacity(4, 8);
        let a = g.add_process(process(1), Attribution::Orphan).unwrap();
        let b = g.add_process(process(2), Attribution::Orphan).unwrap();
        let c = g.add_process(process(3), Attribution::Orphan).unwrap();
        g.add_edge(a, b, EdgeKind::Spawned).unwrap();
        g.add_edge(b, c, EdgeKind::Spawned).unwrap();
        assert_eq!(g.add_edge(c, a, EdgeKind::Spawned), Err(GraphError::Cycle));
        assert_eq!(
            g.add_edge(a, a, EdgeKind::Spawned),
            Err(GraphError::Cycle),
            "self-loop"
        );
        // A parallel edge along the existing direction is fine: still a DAG.
        g.add_edge(a, c, EdgeKind::Spawned).unwrap();
        assert_eq!(g.stats().refused_cycles, 2);
        assert_eq!(g.stats().unmatched, 3);
        assert_eq!(g.validate(), Ok(()));
    }

    #[test]
    fn a_process_has_one_parent_or_is_an_orphan_on_purpose() {
        let mut g = Graph::with_capacity(8, 8);
        let tc1 = g.add_node(tool_call(1)).unwrap();
        let tc2 = g.add_node(tool_call(2)).unwrap();
        assert_eq!(
            g.add_node(process(7)),
            Err(GraphError::ProcessNeedsAttribution)
        );
        let p = g
            .add_process(process(7), Attribution::ExecutedAs(tc1))
            .unwrap();
        assert_eq!(
            g.add_edge(tc2, p, EdgeKind::ExecutedAs),
            Err(GraphError::SecondParent {
                process: p,
                existing: tc1
            })
        );
        assert_eq!(g.stats().refused_second_parent, 1);
        let o = g.add_process(process(8), Attribution::Orphan).unwrap();
        assert!(g.is_orphan(o));
        assert_eq!(g.parent_of(o), None);
        assert_eq!(g.stats().unmatched, 1);
        // An orphan may still gain lineage edges; that does not make it attributed.
        g.add_edge(p, o, EdgeKind::Spawned).unwrap();
        assert!(g.is_orphan(o));
        assert_eq!(g.validate(), Ok(()));
    }

    #[test]
    fn attribution_to_a_non_tool_call_is_refused_and_adds_no_node() {
        let mut g = Graph::with_capacity(4, 4);
        let f = g.add_node(file()).unwrap();
        let unknown = NodeId(99);
        assert_eq!(
            g.add_process(process(1), Attribution::ExecutedAs(unknown)),
            Err(GraphError::UnknownNode(unknown))
        );
        assert!(matches!(
            g.add_process(process(1), Attribution::ExecutedAs(f)),
            Err(GraphError::Endpoints {
                kind: EdgeKind::ExecutedAs,
                from: NodeKind::File,
                ..
            })
        ));
        assert_eq!(g.stats().nodes, 1);
        assert_eq!(g.stats().refused_endpoints, 1);
    }

    #[test]
    fn a_full_graph_refuses_and_does_not_grow() {
        let mut small = Graph::with_capacity(2, 1);
        let (node_cap, edge_cap) = (small.nodes.capacity(), small.edges.capacity());
        let first = small.add_process(process(1), Attribution::Orphan).unwrap();
        let second = small.add_process(process(2), Attribution::Orphan).unwrap();
        assert_eq!(
            small.add_process(process(3), Attribution::Orphan),
            Err(GraphError::Full)
        );
        assert_eq!(small.add_node(file()), Err(GraphError::Full));
        small.add_edge(first, second, EdgeKind::Spawned).unwrap();
        assert_eq!(
            small.add_edge(first, second, EdgeKind::TaintedBy),
            Err(GraphError::Endpoints {
                kind: EdgeKind::TaintedBy,
                from: NodeKind::Process,
                to: NodeKind::Process
            })
        );
        assert_eq!(
            small.add_edge(second, first, EdgeKind::Spawned),
            Err(GraphError::Cycle)
        );
        assert_eq!(small.stats().refused_full, 2);
        assert_eq!(
            (small.nodes.capacity(), small.edges.capacity()),
            (node_cap, edge_cap)
        );
        // Room for no more edges: a valid one is refused as Full.
        let mut one_edge = Graph::with_capacity(3, 1);
        let x = one_edge
            .add_process(process(1), Attribution::Orphan)
            .unwrap();
        let y = one_edge
            .add_process(process(2), Attribution::Orphan)
            .unwrap();
        let z = one_edge
            .add_process(process(3), Attribution::Orphan)
            .unwrap();
        one_edge.add_edge(x, y, EdgeKind::Spawned).unwrap();
        assert_eq!(
            one_edge.add_edge(y, z, EdgeKind::Spawned),
            Err(GraphError::Full)
        );
        assert_eq!(one_edge.stats().refused_full, 1);
    }

    #[test]
    fn the_cycle_search_stays_correct_across_many_epochs() {
        // A long chain plus repeated probes: epoch marks must never make a
        // reachable node look unreachable, or the reverse.
        let n = 200;
        let mut g = Graph::with_capacity(n, 2 * n);
        let ids: Vec<NodeId> = (0..n)
            .map(|i| {
                g.add_process(process(u32::try_from(i).unwrap()), Attribution::Orphan)
                    .unwrap()
            })
            .collect();
        for w in ids.windows(2) {
            g.add_edge(w[0], w[1], EdgeKind::Spawned).unwrap();
        }
        for i in (0..n).step_by(7) {
            for j in (i + 1..n).step_by(13) {
                assert_eq!(
                    g.add_edge(ids[j], ids[i], EdgeKind::Spawned),
                    Err(GraphError::Cycle),
                    "{j}->{i}"
                );
            }
        }
        assert_eq!(g.validate(), Ok(()));
    }
}
