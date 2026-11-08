"""Visualize one Neo4j product as tier hyperedges and connection arrows."""

import argparse
from getpass import getpass
import json
import os
from pathlib import Path
import re
import sys
import textwrap
import warnings

import hypernetx as hnx
import networkx as nx
import neo4j
import pandas as pd


def build_hypergraph(data, include_touchpoints=True):
    """Keep database IDs as identities and human-readable labels for display."""
    if int(pd.__version__.split(".")[0]) >= 3:
        raise ValueError(
            "HyperNetX 2.3.13 needs pandas below 3. "
            "Install this section's dependencies with python -m pip install -r requirements.txt."
        )
    if not isinstance(data, dict) or not isinstance(data.get("nodes"), list) or not isinstance(data.get("edges"), list):
        raise ValueError("The JSON export must contain 'nodes' and 'edges' lists.")
    graph = nx.DiGraph()
    tiers = {}
    nodes = {}
    for node in data["nodes"]:
        node_id = node.get("id")
        if not isinstance(node_id, str) or not node_id.strip():
            raise ValueError("Every exported node must have a non-empty string id.")
        if node_id in nodes:
            raise ValueError(f"Duplicate node id: {node_id}")
        nodes[node_id] = node
        labels = node.get("labels", [])
        if "Product" in labels:
            continue
        if "Tier" in labels:
            tiers[node_id] = {
                "label": str(node.get("label") or node_id[:8]),
                "members": set(),
                "touchpoints": set(),
            }
        elif "Component" in labels or "Connection" in labels:
            kind = "Component" if "Component" in labels else "Connection"
            display = (
                node.get("connection_id") if kind == "Connection" else node.get("label")
            ) or node.get("name") or node_id[:8]
            graph.add_node(node_id, display=str(display), kind=kind)

    for edge in data["edges"]:
        source, target = edge["src"], edge["tgt"]
        relation = edge["rel"]
        if source not in nodes or target not in nodes:
            warnings.warn(f"Skipping {relation} with an endpoint outside this product.")
            continue
        if relation == "CONTAINS" and source in tiers and target in graph:
            tiers[source]["members"].add(target)
        elif (
            relation == "HAS_TOUCHPOINT_IN"
            and source in graph
            and graph.nodes[source]["kind"] == "Connection"
            and target in tiers
        ):
            tiers[target]["touchpoints"].add(source)
        elif relation == "CONNECTS" and source in graph and target in graph:
            graph.add_edge(source, target)

    memberships = {}
    for tier_id, tier in tiers.items():
        members = tier["members"] | (tier["touchpoints"] if include_touchpoints else set())
        if members:
            memberships[tier_id] = sorted(members)
        else:
            warnings.warn(f"Tier {tier['label']} has no drawable members.")
    hypergraph = hnx.Hypergraph(memberships)
    if not graph:
        raise ValueError("This product has no Component or Connection nodes to draw.")
    for node_id, attributes in graph.nodes(data=True):
        if attributes["kind"] == "Connection" and graph.degree(node_id) == 0:
            warnings.warn(f"Connection {attributes['display']} has no CONNECTS relationships.")
    return hypergraph, graph, tiers


def list_products(transaction):
    return transaction.run("""
        MATCH (product:Product)
        RETURN product.id AS id, product.brand AS brand, product.model AS model
        ORDER BY brand, model, id
    """).data()


def query_product(transaction, product_id):
    metadata = transaction.run("""
        MATCH (product:Product {id: $product_id})
        RETURN product.brand AS brand, product.model AS model, product.desc AS desc
    """, product_id=product_id).single()
    if metadata is None:
        raise ValueError(f"No Product found with id {product_id!r}.")
    nodes = transaction.run("""
        MATCH (node)
        WHERE node.product_id = $product_id OR node.id = $product_id
        RETURN node.id AS id, labels(node) AS labels, node.label AS label,
               node.name AS name, node.connection_id AS connection_id
        ORDER BY id
    """, product_id=product_id).data()
    edges = transaction.run("""
        MATCH (source)-[relationship]->(target)
        WHERE (source.product_id = $product_id OR source.id = $product_id)
          AND (target.product_id = $product_id OR target.id = $product_id)
        RETURN source.id AS src, target.id AS tgt, type(relationship) AS rel
        ORDER BY src, tgt, rel
    """, product_id=product_id).data()
    return {"product_id": product_id, "meta": dict(metadata), "nodes": nodes, "edges": edges}


def choose_product(products):
    if not products:
        raise ValueError("There are no Product nodes in this database. Import a product first.")
    for index, product in enumerate(products, start=1):
        title = " ".join(str(product.get(key) or "") for key in ("brand", "model")).strip()
        print(f"{index}. {title or 'Unnamed product'} [{product['id']}]")
    if not sys.stdin.isatty():
        raise ValueError("Use --product-id UUID when running without an interactive terminal.")
    while True:
        choice = input("Select a product number: ").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(products):
            return products[int(choice) - 1]["id"]
        print(f"Enter a number from 1 to {len(products)}.")


def draw_hypergraph(hypergraph, graph, tiers, metadata, size=(18, 12)):
    import matplotlib.pyplot as plt
    from matplotlib.lines import Line2D

    layout_graph = nx.Graph()
    layout_graph.add_nodes_from(sorted(graph))
    layout_graph.add_edges_from(graph.edges, weight=0.5)
    for tier_id in hypergraph.edges:
        layout_graph.add_node(tier_id)
        layout_graph.add_edges_from(
            ((tier_id, member) for member in hypergraph.edges[tier_id]), weight=1.5
        )
    positions = nx.spring_layout(layout_graph, seed=42, iterations=150, scale=5)
    figure, axis = plt.subplots(figsize=size, layout="constrained")
    axis.set_facecolor("#fafafa")
    if len(hypergraph.edges):
        palette = plt.get_cmap("tab20")
        colors = [palette(index % 20) for index in range(len(hypergraph.edges))]
        hnx.draw(
            hypergraph,
            pos=positions,
            ax=axis,
            with_node_labels=False,
            edge_labels={tier_id: tiers[tier_id]["label"] for tier_id in hypergraph.edges},
            edge_labels_kwargs={"fontsize": 10, "fontweight": "bold"},
            edges_kwargs={
                "facecolors": [(*color[:3], 0.16) for color in colors],
                "edgecolors": colors,
                "linewidths": 1.5,
            },
            nodes_kwargs={"alpha": 0},
        )
    nx.draw_networkx_edges(
        graph, positions, ax=axis, arrows=True, arrowsize=16,
        edge_color="#555555", width=1, alpha=0.7,
        node_size=260, connectionstyle="arc3,rad=0.06",
    )
    for kind, color, shape in (("Component", "#087f8c", "o"), ("Connection", "#c44536", "s")):
        members = [node_id for node_id in graph if graph.nodes[node_id]["kind"] == kind]
        if members:
            nx.draw_networkx_nodes(
                graph, positions, ax=axis, nodelist=members,
                node_color=color, node_shape=shape, node_size=260,
                edgecolors="white", linewidths=1,
            )
    for node_id, attributes in graph.nodes(data=True):
        axis.annotate(
            textwrap.fill(attributes["display"], width=18), positions[node_id],
            xytext=(0, 11), textcoords="offset points", ha="center", va="bottom",
            fontsize=8, color="#222222",
            bbox={"facecolor": "white", "edgecolor": "none", "alpha": 0.8, "pad": 1},
        )
    title = " ".join(str(metadata.get(key) or "") for key in ("brand", "model")).strip()
    description = str(metadata.get("desc") or "")
    axis.set_title(
        textwrap.fill(title or "Product hypergraph", 80)
        + ("\n" + textwrap.fill(description, 100) if description else ""),
        fontsize=14, pad=20,
    )
    axis.legend(handles=[
        Line2D([], [], marker="o", color="none", markerfacecolor="#087f8c", label="Component"),
        Line2D([], [], marker="s", color="none", markerfacecolor="#c44536", label="Connection"),
        Line2D([], [], color="#555555", label="CONNECTS (arrows)"),
    ], loc="lower left", frameon=False)
    axis.margins(0.15)
    axis.set_aspect("equal")
    axis.axis("off")
    return figure


def parse_arguments(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group()
    source.add_argument("--product-id", help="Product UUID printed by the import script.")
    source.add_argument("--input-json", type=Path, help="Redraw a previous JSON export without Neo4j.")
    source.add_argument("--list-products", action="store_true", help="List product IDs without drawing.")
    parser.add_argument("--uri", default=os.environ.get("NEO4J_URI", "bolt://remanserver:7687"))
    parser.add_argument("--username", default=os.environ.get("NEO4J_USERNAME", "neo4j"))
    parser.add_argument("--database", default=os.environ.get("NEO4J_DATABASE", "neo4j"))
    parser.add_argument("--output", type=Path, default=Path(__file__).resolve().parent / "output")
    parser.add_argument("--no-touchpoints", action="store_true", help="Group only direct CONTAINS members.")
    parser.add_argument("--no-show", action="store_true", help="Save files without opening a plot window.")
    parser.add_argument("--width", type=float, default=18, help="Figure width in inches.")
    parser.add_argument("--height", type=float, default=12, help="Figure height in inches.")
    arguments = parser.parse_args(argv)
    if not (0 < arguments.width <= 100 and 0 < arguments.height <= 100):
        parser.error("Figure dimensions must be greater than 0 and at most 100 inches.")
    return arguments


def main(argv=None):
    arguments = parse_arguments(argv)
    try:
        if arguments.input_json:
            with arguments.input_json.open(encoding="utf-8") as source:
                data = json.load(source)
        else:
            password = os.environ.get("NEO4J_PASSWORD")
            if not password:
                if not sys.stdin.isatty():
                    raise ValueError("Set NEO4J_PASSWORD when running without an interactive terminal.")
                password = getpass("Neo4j password (hidden): ")
                if not password:
                    raise ValueError("A Neo4j password is required.")
            with neo4j.GraphDatabase.driver(arguments.uri, auth=(arguments.username, password)) as driver:
                driver.verify_connectivity()
                with driver.session(database=arguments.database, default_access_mode=neo4j.READ_ACCESS) as session:
                    if arguments.list_products:
                        products = session.execute_read(list_products)
                        if not products:
                            print("No products found.")
                        for product in products:
                            print(f"{product['id']}  {product.get('brand') or ''} {product.get('model') or ''}")
                        return 0
                    product_id = arguments.product_id or choose_product(session.execute_read(list_products))
                    data = session.execute_read(query_product, product_id)
        hypergraph, graph, tiers = build_hypergraph(data, not arguments.no_touchpoints)
        if arguments.no_show:
            import matplotlib
            matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        figure = draw_hypergraph(hypergraph, graph, tiers, data.get("meta", {}), (arguments.width, arguments.height))
        try:
            arguments.output.mkdir(parents=True, exist_ok=True)
            product_id = str(data.get("product_id") or "export")
            safe_id = re.sub(r"[^A-Za-z0-9_-]", "_", product_id)[:100] or "export"
            stem = arguments.output / f"hypergraph_{safe_id}"
            for extension in ("png", "pdf"):
                destination = stem.with_suffix(f".{extension}")
                figure.savefig(destination, dpi=180, facecolor="white")
                print(f"Saved: {destination.resolve()}")
            destination = stem.with_suffix(".json")
            with destination.open("w", encoding="utf-8") as export:
                json.dump(data, export, indent=2, ensure_ascii=False)
                export.write("\n")
            print(f"Saved: {destination.resolve()}")
            print(f"{graph.number_of_nodes()} nodes; {len(hypergraph.edges)} tier hyperedges; {graph.number_of_edges()} CONNECTS arrows.")
            if not arguments.no_show:
                plt.show()
        finally:
            plt.close(figure)
    except (ValueError, OSError, KeyError, TypeError, neo4j.exceptions.Neo4jError, neo4j.exceptions.DriverError) as error:
        print(f"Hypergraph generation failed: {error}", file=sys.stderr)
        return 1
    except (KeyboardInterrupt, EOFError):
        print("Cancelled.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())