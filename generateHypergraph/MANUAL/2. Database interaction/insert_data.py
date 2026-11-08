# %% [markdown]
# ### Creating node
# ```cypher
# MERGE (casing:Part {id:"P1", name:"Outer Casing"})
# ```
#
# ### Connecting nodes
# ```cypher
# MERGE (c2)-[:REQUIRES_TOOL]->(spudger)
# ```
#
# ### Match all query
#
# ```cypher
# MATCH (n)
# OPTIONAL MATCH (n)-[r]->(m)
# RETURN n, r, m
# LIMIT 1000
# ```
#
# ```cypher
# MATCH (n)
# DETACH DELETE n;
# ```

# %%
import neo4j
import pandas as pd
import uuid

print("=" * 50)
print("Excel to Neo4j database script")
print("27-05-2026")
print("Lectoraat Smart Sustainable Manufacturing - THUAS")
print("=" * 50)
print()

while True:
    name = input("Enter the Excel filename (including .xlsx): ").strip()

    if not name:
        print("Filename cannot be empty. Please try again.\n")
        continue

    if not name.endswith(".xlsx"):
        print("Please include the .xlsx extension.\n")
        continue

    break

print()
print(f"✔ Importing data from: {name}")
print("-" * 50)

# %%
PATH = name

# ------------- Nodes -------------------
df_product      = pd.read_excel(PATH, sheet_name="Product")
df_components   = pd.read_excel(PATH, sheet_name="Component-list")
df_connections  = pd.read_excel(PATH, sheet_name="Connection-list")
df_tiers        = pd.read_excel(PATH, sheet_name="Tier-list")

# ------------- UUID's -------------------
df_product['uuid4']      = [str(uuid.uuid4()) for _ in range(len(df_product))]
df_components['uuid4']   = [str(uuid.uuid4()) for _ in range(len(df_components))]
df_connections['uuid4']  = [str(uuid.uuid4()) for _ in range(len(df_connections))]
df_tiers['uuid4']        = [str(uuid.uuid4()) for _ in range(len(df_tiers))]

# --------- Pre-filter df ----------------
df_connections = df_connections[~df_connections["Connection ID"].isna()]

df_tiers = df_tiers[
    ~(df_tiers["Components"].isna() &
      df_tiers["Connections"].isna() &
      df_tiers["Connector 'touchpoints'"].isna())
]

# ------------ Mega lookup dict ----------
lookup_dict = {}
product_uuid = df_product.iloc[0]['uuid4']

for index, row in df_components.iterrows():
    lookup_dict[row["Label"]] = row["uuid4"]

for index, row in df_connections.iterrows():
    lookup_dict[row["Connection ID"].strip()] = row["uuid4"]

for index, row in df_tiers.iterrows():
    lookup_dict[row["Tier"].strip()] = row["uuid4"]

# ------------- Edges ----------------------
con_edge_dict = {}

for connection, data in df_connections.iterrows():
    label = data["Connection ID"]

    if pd.isna(label):
        print('NaN found in connections: connection row is empty or has no label')
        continue

    connects = data["Connects"]

    if pd.isna(connects):
        print("NaN found in connections: connection is related to no part")
        connects_list = ""
    else:
        connects_list = [x.strip() for x in str(connects).split(",")]

    con_edge_dict[label] = connects_list

tier_edge_dict_com      = {}
tier_edge_dict_con      = {}
tier_edge_dict_touch    = {}

for tier, data in df_tiers.iterrows():
    components  = data["Components"]
    connections = data["Connections"]
    touchpoints = data["Connector 'touchpoints'"]

    if pd.isna(components) and pd.isna(connections) and pd.isna(touchpoints):
        print("Empty tier found: contains no components, connections or touchpoints")
        continue

    label = data["Tier"].strip()

    if pd.isna(components):
        print("NaN found in components list of a tier: tier contains component")
    else:
        components_list = [x.strip() for x in str(components).split(",")]
        tier_edge_dict_com[label] = components_list

    if pd.isna(connections):
        print("NaN found in connections list of a tier: tier contains connection")
    else:
        connections_list = [x.strip() for x in str(connections).split(",")]
        tier_edge_dict_con[label] = connections_list

    if pd.isna(touchpoints):
        print("NaN found in touchpoints: tier contains no touchpoints")
    else:
        touchpoints_list = [x.strip() for x in str(touchpoints).split(",")]
        for connection in touchpoints_list:
            tier_edge_dict_touch.setdefault(connection, []).append(label)


def dict_to_dataframe(data: dict) -> pd.DataFrame:
    records = []
    for source, targets in data.items():
        for target in targets:
            records.append({"source_id": lookup_dict[source], "target_id": lookup_dict[target]})
    return pd.DataFrame(records)

df_edge_connections = dict_to_dataframe(con_edge_dict)
df_tier_components  = dict_to_dataframe(tier_edge_dict_com)
df_tier_connections = dict_to_dataframe(tier_edge_dict_con)
df_tier_touchpoints = dict_to_dataframe(tier_edge_dict_touch)


# %%
# ==================== HELPER: EXTRA COLUMNS ====================

def get_extra_properties(df: pd.DataFrame, known_columns: list) -> pd.DataFrame:
    """
    Returns a copy of df with an added 'extras' column.
    'extras' is a dict of any columns NOT in known_columns (and not uuid4).
    NaN values are dropped entirely (not sent to Neo4j) so no APOC is needed.

    Any leftover/unknown columns are automatically stored as additional node properties.
    """
    reserved = set(known_columns + ["uuid4"])
    extra_cols = [c for c in df.columns if c not in reserved]

    if extra_cols:
        print(f"  -> Extra columns detected and will be added as properties: {extra_cols}")

    def row_extras(row):
        # Drop NaN values in Python — keeps Cypher simple, no APOC required
        return {
            col: row[col]
            for col in extra_cols
            if not pd.isna(row[col])
        }

    result = df.copy()
    result["extras"] = result.apply(row_extras, axis=1)
    return result


# ==================== NODE CREATOR FUNCTIONS ====================

def batch_create_products(tx, df: pd.DataFrame):
    """
    Creates Product nodes.
    Known columns are mapped to explicit properties.
    Any extra columns are automatically added as additional properties.
    """
    known = ["Brand Name", "Model", "General Description"]
    df = get_extra_properties(df, known)

    tx.run("""
        UNWIND $rows AS row
        CREATE (p:Product {
            id:         row.uuid4,
            product_id: row.uuid4,
            brand:      row['Brand Name'],
            model:      row['Model'],
            desc:       row['General Description']
        })
        SET p += row.extras
    """, rows=df.to_dict("records"))


def batch_create_components(tx, df: pd.DataFrame, product_uuid: str):
    """
    Creates Component nodes.
    Known columns are mapped to explicit properties.
    Any extra columns are automatically added as additional properties.
    """
    known = ["Label", "Name", "#", "Description", "Material", "Weight"]
    df = get_extra_properties(df, known)

    tx.run("""
        UNWIND $rows AS row
        CREATE (c:Component {
            id:          row.uuid4,
            product_id:  $product_id,
            label:       row.Label,
            name:        row.Name,
            amount:      row['#'],
            description: row.Description,
            material:    row.Material,
            weight:      row.Weight
        })
        SET c += row.extras
    """, rows=df.to_dict("records"), product_id=product_uuid)


def batch_create_connections(tx, df: pd.DataFrame, product_uuid: str):
    """
    Creates Connection nodes.
    Known columns are mapped to explicit properties.
    Any extra columns are automatically added as additional properties.
    """
    known = [
        "Connection ID", "Type", "#", "Accessibility", "orientation",
        "Removal direction", "Connects", "Accessible after", "Tier",
        "Typical release tool"
    ]
    df = get_extra_properties(df, known)

    tx.run("""
        UNWIND $rows AS row
        CREATE (con:Connection {
            id:                 row.uuid4,
            product_id:         $product_id,
            connection_id:      row['Connection ID'],
            type:               row.Type,
            amount:             row['#'],
            accessibility:      row.Accessibility,
            orientation:        row.orientation,
            removal_direction:  row['Removal direction'],
            connects:           row.Connects,
            accessible_after:   row['Accessible after'],
            tier:               row.Tier,
            tool:               row['Typical release tool']
        })
        SET con += row.extras
    """, rows=df.to_dict("records"), product_id=product_uuid)


def batch_create_tiers(tx, df: pd.DataFrame, product_uuid: str):
    """
    Creates Tier nodes.
    Known columns are mapped to explicit properties.
    Any extra columns are automatically added as additional properties.
    """
    known = ["Tier", "Components", "Connections", "Connector 'touchpoints'"]
    df = get_extra_properties(df, known)

    tx.run("""
        UNWIND $rows AS row
        CREATE (t:Tier {
            id:         row.uuid4,
            product_id: $product_id,
            label:      row.Tier
        })
        SET t += row.extras
    """, rows=df.to_dict("records"), product_id=product_uuid)


# %%
# ==================== EDGE CREATOR FUNCTION ====================

def batch_create_relationships(tx, df: pd.DataFrame, relationship_type: str):
    """
    df must have columns: source_id, target_id
    """
    tx.run(f"""
        UNWIND $rows AS row
        MATCH (source {{id: row.source_id}})
        MATCH (target {{id: row.target_id}})
        MERGE (source)-[r:{relationship_type}]->(target)
    """, rows=df.to_dict("records"))


# %%
# REMAN SERVER
NEO4J_URI      = "bolt://remanserver:7687"
NEO4J_USERNAME = "neo4j"
NEO4J_PASSWORD = "YOUR_NEO4J_PASSWORD"
NEO4J_DATABASE = "neo4j"

# NEO4j AURA
# NEO4J_URI="neo4j+ssc://d481b316.databases.neo4j.io"
# NEO4J_USERNAME="d481b316"
# NEO4J_PASSWORD="YOUR_NEO4J_PASSWORD"
# NEO4J_DATABASE="d481b316"

driver = neo4j.GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USERNAME, NEO4J_PASSWORD))

try:
    driver.verify_connectivity()
    print(f"Successfully connected to Neo4j: {NEO4J_URI}")
except Exception as e:
    print(f"Connection failed: {e}")
    raise

with driver.session(database=NEO4J_DATABASE) as session:
    session.execute_write(batch_create_products, df_product)
    print("✓ Products created")
    session.execute_write(batch_create_components, df_components, product_uuid)
    print("✓ Components created")
    session.execute_write(batch_create_connections, df_connections, product_uuid)
    print("✓ Connections created")
    session.execute_write(batch_create_tiers, df_tiers, product_uuid)
    print("✓ Tiers created")
    session.execute_write(batch_create_relationships, df_edge_connections, "CONNECTS")
    print("✓ Connection-Component relationships created")
    session.execute_write(batch_create_relationships, df_tier_components, "CONTAINS")
    print("✓ Tier-Component relationships created")
    session.execute_write(batch_create_relationships, df_tier_connections, "CONTAINS")
    print("✓ Tier-Connection relationships created")
    session.execute_write(batch_create_relationships, df_tier_touchpoints, "HAS_TOUCHPOINT_IN")
    print("✓ Tier-Touchpoint relationships created")
    print("✓ Product connected to top-level items (tiers or floating components and connections)")
    print(f"Product UUID: {product_uuid}")