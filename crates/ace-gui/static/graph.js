// The relationship graph (PLAN.md 5.13): ace3's graph_alert, from saq_analysis.js before ace3 removed it.
// It fetches the alert's graph from the JSON API, at the URL the page's #graph names, and draws it with
// vis.js 4.1.0, which ace3 vendored (vendor/README.md). vis draws on a canvas: a label is painted as
// text with fillText and never reaches the DOM, and no node gets vis's `title`, its one tooltip that
// takes HTML. What this writes into the page, the status line, it writes with textContent.
(function () {
  "use strict";
  var container = document.getElementById("graph");
  var status = document.getElementById("graph-status");
  if (!container || !status) {
    return;
  }

  function say(text) {
    status.textContent = text;
  }

  // How each kind of node looks: ace3's, an analysis a box, an observable a dot and a tag a star.
  var SHAPES = { alert: "box", observable: "dot", result: "box", tag: "star" };

  function draw(graph) {
    var nodes = new vis.DataSet(
      graph.nodes.map(function (node) {
        return {
          id: node.id,
          label: String(node.label),
          group: node.kind,
          shape: SHAPES[node.kind] || "dot",
          size: 10,
        };
      })
    );
    var edges = new vis.DataSet(
      graph.edges.map(function (edge, i) {
        var drawn = { id: i, from: edge.from, to: edge.to, arrows: "to" };
        if (edge.relationship) {
          drawn.label = String(edge.relationship);
          drawn.dashes = true;
        }
        return drawn;
      })
    );
    var network = new vis.Network(
      container,
      { nodes: nodes, edges: edges },
      { nodes: { font: { size: 12 } }, edges: { font: { size: 10, align: "middle" } } }
    );
    // what a test reads to see what the library holds
    container.aceGraph = { network: network, nodes: nodes, edges: edges };
    network.once("stabilized", function () {
      network.fit();
      container.dataset.drawn = "true";
    });
    var said = graph.nodes.length + " nodes and " + graph.edges.length + " edges.";
    say(graph.note ? said + " " + graph.note : said);
  }

  say("Loading the graph.");
  fetch(container.dataset.source, {
    credentials: "same-origin",
    headers: { Accept: "application/json" },
  })
    .then(function (response) {
      if (!response.ok) {
        throw new Error("the API answered " + response.status);
      }
      return response.json();
    })
    .then(draw)
    .catch(function (error) {
      say("The graph couldn't be drawn: " + error.message + ".");
    });
})();
