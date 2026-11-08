# Inputting data

Interacting with the database can be done using python or neo4j's own user interface. For the Remanlab, this interface can be reached using the following link:


[remanserver:7687](remanserver:7474)

After reaching the webpage, the interface can be accessed using the following credentials:

| Key             | Value              |
|-----------------|--------------------|
| NEO4J_USERNAME  | neo4j              |
| NEO4J_PASSWORD  | YOUR_NEO4J_PASSWORD |
| NEO4J_DATABASE  | neo4j              |


## Importing CYPHER queries

To look at data currently residing in the database, a CYPHER query can be done. To speed up the process, there are already some CYPHER queries made.

These can be imported by navigating to 'Saved Cypher' in the menu on the right side of the screen. Find the 'Import saved Cypher' button, and load the 'Cypher_queries.csv' file residing in this folder.

## Saved CYPHER queries

There are currently three queries:

👁️ View Graph: this shows all data in the database
🔍 Find select property: to find a select product, edit this query and change the product_id to the one you're looking for
⚠️ Delete All: this clears the whole database


