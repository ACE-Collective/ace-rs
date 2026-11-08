//! An alert's relationship graph (PLAN.md 5.13): ace3's `/json` view, which fed vis.js in its alert page,
//! as nodes and edges built from the alert's tree (`alert_view`).
//!
//! ace3's graph has a node for the alert, one for each analysis and each observable, and one for each tag,
//! with an edge from an analysis to each observable it added, from an observable to each analysis of it,
//! and from anything tagged to its tag. Here a module's result is the analysis, so the nodes are the
//! alert, its observables, their results and the tags, and the edges are:
//! - `observed`: the alert to each observable the submission added, as ace3's root analysis to its
//!   observables;
//! - `analyzed`: an observable to each result of it;
//! - `added`: a result to each observable it added;
//! - `tagged`: an observable or a result to each of its tags, one node per tag;
//! - `related`: an observable to the observable a relationship names (`analysis.relationships`), with
//!   the relationship's kind, such as `extracted_from`. ace3's graph doesn't draw these; its tree has
//!   them, and they are what makes it a relationship graph.
//!
//! It's bounded: at most `MAX_GRAPH_NODES` nodes and `MAX_GRAPH_EDGES` edges, which a browser can lay out
//! in a few seconds, and an edge only between two nodes it kept. The walk is breadth first from the
//! alert, so what's kept is what's nearest the alert: the submission's observables, their results,
//! what those added, and so on. Relationships come after the tree's own edges. A graph that was cut, or
//! drawn from a tree that was (`MAX_TREE_OBSERVABLES`), says so in its `note`.
//!
//! A label is the alert's title, an observable's type and value (a file's first path), a result's
//! module, or a tag's name, at most `MAX_LABEL_CHARS` characters. Every one is the alert's or a
//! module's text, so whatever draws it draws it as text.

use std::collections::{HashMap, HashSet, VecDeque};

use uuid::Uuid;

use crate::alert_view::{AlertTree, MAX_TREE_OBSERVABLES};
use crate::alerts::AlertObservable;
use crate::{Service, ServiceError};

/// The most nodes a graph holds.
pub const MAX_GRAPH_NODES: usize = 1000;
/// The most edges a graph holds.
pub const MAX_GRAPH_EDGES: usize = 2000;
/// The longest label, in characters; a longer one ends in `…`.
pub const MAX_LABEL_CHARS: usize = 80;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GraphNodeKind {
    Alert,
    Observable,
    Result,
    Tag,
}

impl GraphNodeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            GraphNodeKind::Alert => "alert",
            GraphNodeKind::Observable => "observable",
            GraphNodeKind::Result => "result",
            GraphNodeKind::Tag => "tag",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GraphEdgeKind {
    Observed,
    Analyzed,
    Added,
    Tagged,
    Related,
}

impl GraphEdgeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            GraphEdgeKind::Observed => "observed",
            GraphEdgeKind::Analyzed => "analyzed",
            GraphEdgeKind::Added => "added",
            GraphEdgeKind::Tagged => "tagged",
            GraphEdgeKind::Related => "related",
        }
    }
}

/// One node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphNode {
    /// `alert`, `o<id>`, `r<id>` or `t<n>`, unique in the graph.
    pub id: String,
    pub kind: GraphNodeKind,
    pub label: String,
    /// An observable's id in the alert, as the alert's other routes name it.
    pub observable: Option<i64>,
    /// A result's id in the alert.
    pub result: Option<i64>,
}

/// One edge, between two nodes of the graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphEdge {
    pub from: String,
    pub to: String,
    pub kind: GraphEdgeKind,
    /// A `related` edge's relationship, such as `extracted_from`.
    pub relationship: Option<String>,
}

/// An alert's graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlertGraph {
    pub alert: Uuid,
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
    /// Whether anything was left out, here or in the tree it was drawn from.
    pub truncated: bool,
    /// What was left out, when anything was.
    pub note: Option<String>,
}

/// A label of at most `MAX_LABEL_CHARS` characters.
fn label(text: &str) -> String {
    if text.chars().count() <= MAX_LABEL_CHARS {
        return text.to_owned();
    }
    let mut cut: String = text.chars().take(MAX_LABEL_CHARS - 1).collect();
    cut.push('…');
    cut
}

fn observable_label(observable: &AlertObservable) -> String {
    let value = if observable.kind == "file" {
        observable
            .files
            .first()
            .map_or(observable.value.as_str(), |file| file.path.as_str())
    } else {
        observable.value.as_str()
    };
    label(&format!("{}: {value}", observable.display_label()))
}

/// The graph as it's built: what it kept, and how much there was.
struct Builder {
    max_nodes: usize,
    max_edges: usize,
    nodes: Vec<GraphNode>,
    kept: HashSet<String>,
    seen: HashSet<String>,
    edges: Vec<GraphEdge>,
    all_edges: usize,
    tags: HashMap<String, String>,
}

impl Builder {
    /// Adds a node unless it's there or the graph is full. Either way it counts once.
    fn node(&mut self, node: GraphNode) {
        if !self.seen.insert(node.id.clone()) {
            return;
        }
        if self.nodes.len() < self.max_nodes {
            self.kept.insert(node.id.clone());
            self.nodes.push(node);
        }
    }

    /// Adds an edge if both its ends were kept and the graph has room. Either way it counts.
    fn edge(&mut self, from: &str, to: &str, kind: GraphEdgeKind, relationship: Option<String>) {
        self.all_edges += 1;
        if self.edges.len() < self.max_edges && self.kept.contains(from) && self.kept.contains(to) {
            self.edges.push(GraphEdge {
                from: from.to_owned(),
                to: to.to_owned(),
                kind,
                relationship,
            });
        }
    }

    fn tag(&mut self, from: &str, name: &str) {
        let next = format!("t{}", self.tags.len());
        let id = self.tags.entry(name.to_owned()).or_insert(next).clone();
        self.node(GraphNode {
            id: id.clone(),
            kind: GraphNodeKind::Tag,
            label: label(name),
            observable: None,
            result: None,
        });
        self.edge(from, &id, GraphEdgeKind::Tagged, None);
    }
}

/// The graph of a tree, with at most `max_nodes` nodes and `max_edges` edges. This is what
/// `Service::alert_graph` serves, with `MAX_GRAPH_NODES` and `MAX_GRAPH_EDGES`.
pub fn graph_of(tree: &AlertTree, max_nodes: usize, max_edges: usize) -> AlertGraph {
    let by_id: HashMap<i64, &AlertObservable> =
        tree.observables.iter().map(|o| (o.id, o)).collect();
    let mut added_by: HashMap<i64, Vec<i64>> = HashMap::new();
    let mut added: HashSet<i64> = HashSet::new();
    for addition in &tree.additions {
        let list = added_by.entry(addition.result).or_default();
        if !list.contains(&addition.observable) {
            list.push(addition.observable);
        }
        added.insert(addition.observable);
    }
    let mut graph = Builder {
        max_nodes,
        max_edges,
        nodes: Vec::new(),
        kept: HashSet::new(),
        seen: HashSet::new(),
        edges: Vec::new(),
        all_edges: 0,
        tags: HashMap::new(),
    };
    let observable_node = |observable: &AlertObservable| GraphNode {
        id: format!("o{}", observable.id),
        kind: GraphNodeKind::Observable,
        label: observable_label(observable),
        observable: Some(observable.id),
        result: None,
    };
    graph.node(GraphNode {
        id: "alert".to_owned(),
        kind: GraphNodeKind::Alert,
        label: label(&tree.alert.summary.title),
        observable: None,
        result: None,
    });

    // The submission's observables, then any no result added, then any the walk doesn't reach, as the
    // tree view starts its walks, so every observable is in the walk.
    let mut queue: VecDeque<i64> = VecDeque::new();
    let mut queued: HashSet<i64> = HashSet::new();
    let top: HashSet<i64> = tree.top.iter().copied().collect();
    for observable in tree.observables.iter().filter(|o| top.contains(&o.id)) {
        graph.node(observable_node(observable));
        graph.edge(
            "alert",
            &format!("o{}", observable.id),
            GraphEdgeKind::Observed,
            None,
        );
        if queued.insert(observable.id) {
            queue.push_back(observable.id);
        }
    }
    let unadded: Vec<i64> = tree
        .observables
        .iter()
        .filter(|o| !top.contains(&o.id) && !added.contains(&o.id))
        .map(|o| o.id)
        .collect();
    let mut rest = unadded
        .into_iter()
        .chain(tree.observables.iter().map(|o| o.id));
    let mut order: Vec<i64> = Vec::new();
    while let Some(id) = queue
        .pop_front()
        .or_else(|| rest.by_ref().find(|id| queued.insert(*id)))
    {
        let Some(observable) = by_id.get(&id) else {
            continue;
        };
        order.push(id);
        let from = format!("o{id}");
        graph.node(observable_node(observable));
        for tag in &observable.tags {
            graph.tag(&from, tag);
        }
        for result in &observable.results {
            let node = format!("r{}", result.id);
            graph.node(GraphNode {
                id: node.clone(),
                kind: GraphNodeKind::Result,
                label: label(&result.module),
                observable: None,
                result: Some(result.id),
            });
            graph.edge(&from, &node, GraphEdgeKind::Analyzed, None);
            for tag in &result.tags {
                graph.tag(&node, tag);
            }
            for child in added_by.get(&result.id).into_iter().flatten() {
                // past MAX_TREE_OBSERVABLES, which the note says
                let Some(child) = by_id.get(child) else {
                    continue;
                };
                graph.node(observable_node(child));
                graph.edge(&node, &format!("o{}", child.id), GraphEdgeKind::Added, None);
                if queued.insert(child.id) {
                    queue.push_back(child.id);
                }
            }
        }
    }

    let by_value: HashMap<(&str, &str), i64> = tree
        .observables
        .iter()
        .map(|o| ((o.kind.as_str(), o.value.as_str()), o.id))
        .collect();
    for id in order {
        let observable = by_id[&id];
        for relationship in &observable.relationships {
            let target = (
                relationship.target_type.as_str(),
                relationship.target_value.as_str(),
            );
            if let Some(target) = by_value.get(&target) {
                graph.edge(
                    &format!("o{id}"),
                    &format!("o{target}"),
                    GraphEdgeKind::Related,
                    Some(relationship.kind.clone()),
                );
            }
        }
    }

    let mut notes = Vec::new();
    if tree.truncated {
        notes.push(format!(
            "The alert has more than {MAX_TREE_OBSERVABLES} observables, and this has the first {MAX_TREE_OBSERVABLES}."
        ));
    }
    let all_nodes = graph.seen.len();
    if graph.nodes.len() < all_nodes || graph.edges.len() < graph.all_edges {
        notes.push(format!(
            "The graph was cut short: it shows {} of {all_nodes} nodes and {} of {} edges, those nearest the alert.",
            graph.nodes.len(),
            graph.edges.len(),
            graph.all_edges,
        ));
    }
    AlertGraph {
        alert: tree.alert.summary.id,
        nodes: graph.nodes,
        edges: graph.edges,
        truncated: !notes.is_empty(),
        note: (!notes.is_empty()).then(|| notes.join(" ")),
    }
}

impl Service {
    /// An alert's relationship graph, from one snapshot of its tree (`alert_tree`). It needs
    /// `alert:read`.
    pub async fn alert_graph(
        &self,
        actor: &crate::Actor,
        id: Uuid,
    ) -> Result<AlertGraph, ServiceError> {
        let tree = self.alert_tree(actor, id).await?;
        Ok(graph_of(&tree, MAX_GRAPH_NODES, MAX_GRAPH_EDGES))
    }
}
