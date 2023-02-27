# neo4j
## Code Snippets
```cypher
// Delete all nodes with their chil nodes
MATCH (n)
DETACH DELETE n


// LOAD CSV file and parse it
LOAD CSV WITH HEADERS FROM 'file:///NSGs.csv' AS line
MERGE (src: host { host:  line.Source } )
MERGE (dst: host { host:  line.Destination } )
MERGE (dst) - [:HAS_PORT] -> (port: port { portNum: line.Destination_Port } )
MERGE (src) - [ALLOW:ALLOW {ALLOW: "ALLOW"} ] -> (port)  

// Alternatively
LOAD CSV WITH HEADERS FROM 'file:///NSGs.csv' AS line
MERGE (srcHost: srcHost { host:  line.Source_Name } )
MERGE (dstHost: dstHost { host:  line.Destination } )
MERGE (srcHost) - [PORT: ALLOW { dstPort: line.Destination_Port }  ] -> (dstHost)
																		 

// Get Graph Representation
WITH *
Match (n)
return n
```
## resources
[Introduction to Cypher - Getting Started (neo4j.com)](https://neo4j.com/docs/getting-started/current/cypher-intro/)
[Importing CSV data into Neo4j - Getting Started](https://neo4j.com/docs/getting-started/current/data-import/csv-import/)
[Default file locations - Operations Manual (neo4j.com)](https://neo4j.com/docs/operations-manual/5/configuration/file-locations/)
[How-To: Import CSV Data with Neo4j Desktop - Developer Guides](https://neo4j.com/developer/desktop-csv-import/)
[training/0123_importing_data.adoc at master · neo4j-contrib/training (github.com)](https://github.com/neo4j-contrib/training/blob/master/online/cypher/60-Minute-Cypher/0123_importing_data.adoc)