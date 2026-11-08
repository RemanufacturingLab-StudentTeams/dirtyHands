# Generating a product hypergraph

This section reads a product from Neo4j and creates a labelled hypergraph. It does not insert, change, or delete anything in the database. Import your Excel file using section 2 first.

## Installing this section's dependencies

Open Command Prompt and navigate to this folder. Replace the example path with your own location:

```cmd
cd /d "C:\Users\niels\Documents\2026 Lectoraat SSM\2026 Dirty Hands 2.0\MANUAL\3. Hypergraph"
```

Create a separate environment so this section does not change the packages used by your other scripts:

```cmd
python -m venv .venv
.venv\Scripts\activate
python -m pip install -r requirements.txt
```

Python 3.14 with pandas 2.3.3 and HyperNetX 2.3.13 was used for offline validation. HyperNetX 2.3.13 is not compatible with pandas 3; use this section's requirements instead of upgrading pandas independently. In a new Command Prompt window, navigate here and activate the environment again.

## Connecting to Neo4j

Your computer must be able to reach the Reman server on its local network or through an appropriate VPN. The defaults are:

| Setting | Default |
|---------|---------|
| URI | `bolt://remanserver:7687` |
| Username | `neo4j` |
| Database | `neo4j` |

Run:

```cmd
python generate_hypergraph.py
```

Enter your Neo4j password when prompted. The password is hidden and is not saved in the script or export. Obtain it from your database administrator. The script then lists products with their UUIDs; enter the number of the product to draw.

To use another server, supply its connection details:

```cmd
python generate_hypergraph.py --uri "neo4j+s://YOUR_INSTANCE.databases.neo4j.io" --username "YOUR_USERNAME" --database "YOUR_DATABASE"
```

Alternatively, the script reads `NEO4J_URI`, `NEO4J_USERNAME`, `NEO4J_DATABASE`, and `NEO4J_PASSWORD` from environment variables. A non-interactive run needs `NEO4J_PASSWORD` and `--product-id`. Do not put real passwords in shared scripts, documentation, or version control.

## Selecting a specific product

List the available products without drawing:

```cmd
python generate_hypergraph.py --list-products
```

Use the UUID printed by the import script or product listing:

```cmd
python generate_hypergraph.py --product-id "YOUR_PRODUCT_UUID"
```

The lookup uses `product_id`, so it works even when the Product node has no relationships to its components or tiers. Separate imports have different UUIDs and appear as separate products.

## Reading the figure

- Teal circles represent components, labelled with their Excel labels.
- Red squares represent connections, labelled with their connection IDs.
- Coloured outlines represent tiers: each tier is one hyperedge containing its `CONTAINS` members.
- By default, a connection with `HAS_TOUCHPOINT_IN` to a tier is also included in that tier's hyperedge. This represents touchpoint participation, not a new database containment relationship.
- Arrows represent the stored direction of `CONNECTS`, normally from a connection to a component. They do not represent disassembly order.
- Nodes without tier membership remain visible outside the tier grouping. A node can participate in multiple tiers.

To show only direct `CONTAINS` membership, excluding touchpoint participation:

```cmd
python generate_hypergraph.py --product-id "YOUR_PRODUCT_UUID" --no-touchpoints
```

Tier outlines are a visual aid. Overlapping outlines can visually enclose unrelated nodes; use the exported JSON relationships to check exact membership. The layout is deterministic for the same data but is not a disassembly sequence or a geometric model of the product.

## Saved files and offline use

Each successful run creates three files in the `output` folder next to the script:

- `hypergraph_UUID.png`: image for viewing and presentations.
- `hypergraph_UUID.pdf`: vector figure for zooming and printing.
- `hypergraph_UUID.json`: product metadata, nodes, and relationships for offline redrawing.

Running again with the same product UUID and output folder replaces these files. Choose another output folder to preserve an earlier version:

```cmd
python generate_hypergraph.py --product-id "YOUR_PRODUCT_UUID" --output "results\version-2" --no-show
```

The `--no-show` option saves the files without opening a plot window. The JSON contains product data but no login credentials; check whether that product data may be shared before distributing it.

Redraw a previous export without any database access or password:

```cmd
python generate_hypergraph.py --input-json "output\hypergraph_UUID.json" --output "results\redrawn" --no-show
```

The JSON must be an export from this script; the workspace's other JSON files may use different structures. Apply `--no-touchpoints` again if required. For a larger figure, use `--width` and `--height` in inches, for example `--width 24 --height 16`.

## Troubleshooting

| Message or symptom | Action |
|--------------------|--------|
| `python` is not recognized | Check your Python installation and use the interpreter command available on your computer. |
| `ModuleNotFoundError` | Activate this section's environment and run its dependency installation command. |
| pandas compatibility error | Reinstall from this section's requirements; pandas must remain below version 3. |
| Server cannot be reached | Check the URI, network/VPN connection, server availability, and firewall access. |
| Authentication failed | Check your username, database, and password with the administrator. |
| No products found | Confirm the selected database and import a product using section 2. |
| Product UUID not found | Copy the exact UUID from `--list-products`; Excel labels are not product UUIDs. |
| Connection has no `CONNECTS` relationships | Check that connection's Excel `Connects` field. The node is still drawn; the warning may indicate missing data. |
| Tier has no drawable members | Check its containment and touchpoint data. An empty hyperedge is omitted from the figure. |
| Labels are crowded | Open the PDF and zoom, or generate a larger figure using `--width` and `--height`. |

The generator cannot reconstruct relationships missing from the database and does not repair imported data. Live server authentication and queries must be checked against your own Neo4j installation; offline validation does not verify server access.