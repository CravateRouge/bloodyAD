from neo4j import GraphDatabase

class Database:

    def __init__(self, uri, user, password):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))
        self._prepareDb()

    def getPrivescPath(self, source, target):
        with self.driver.session() as session:
            relationships = session.read_transaction(self._findShortestPath, source, target)
        return relationships

    def close(self):
        self.driver.close()
    
    def _prepareDb(self):
        with self.driver.session() as session:
            session.write_transaction(self._setWeight)
   
    @staticmethod
    def _setWeight(tx):
        tx.run("MATCH (n)-[r:MemberOf]->(m:Group) SET r.bloodycost = 0 ")
        tx.run("MATCH (n)-[r:AddMember|GenericAll|GenericWrite|AllExtendedRights]->(m:Group) SET r.bloodycost = 1 ")
        tx.run("MATCH (n)-[r:WriteOwner]->(m:Group) SET r.bloodycost = 3 ")
        tx.run("MATCH (n)-[r:WriteDacl|Owns]->(m:Group) SET r.bloodycost = 2 ")
        # These privileges on user objects are not wanted since they work only when resetting passwords
        tx.run("MATCH (n)-[r:WriteDacl|Owns|WriteOwner|GenericAll|GenericWrite|ForceChangePassword|AllExtendedRights]->(m:User) SET r.bloodycost = 200 ")
        tx.run("MATCH (n)-[r:WriteDacl]->(m:Domain) SET r.bloodycost = 1 ")
        tx.run("MATCH (n)-[r:DCSync|GetChangesAll|AllExtendedRights]->(m:Domain) SET r.bloodycost = 0")

    # TODO: Alternative with only CYPHER https://neo4j.com/blog/journey-planning-why-i-love-cypher/ - https://liberation-data.com/saxeburg-series/2018/11/28/rock-n-roll-traffic-routing.html
    # CONS: Less efficient, more complex PROS: Doesn't need GDS plugin and weight setting
    @staticmethod 
    def _findShortestPath(tx, source, target):
        # result = tx.run("MATCH (source {name: $source}), (target {name: $target}) "
        # "CALL gds.shortestPath.dijkstra.stream({"
        # "nodeQuery:'MATCH (n) RETURN id(n) AS id, labels(n) AS labels', "
        # "relationshipQuery:'MATCH (n)-[r]->(m) RETURN id(n) AS source, id(m) AS target, r.bloodycost as bloodycost', "
        # "sourceNode: source, targetNode: target, relationshipWeightProperty: 'bloodycost'}) "
        # "YIELD path "
        # "RETURN path", source=source, target=target)
        result = tx.run("MATCH (s {name:$source}), (t {name:$target}) "
        "CALL gds.shortestPath.dijkstra.stream({ "
        "sourceNode:s, targetNode:t, relationshipWeightProperty:'bloodycost', "
        "nodeProjection:'*', relationshipProjection:{all:{type:'*', properties:'bloodycost'}}}) "
        "YIELD path RETURN path",source=source, target=target)
        return result.single()[0].relationships
    
    @staticmethod
    def _retrieveCheaperEdge(tx, start, end):
        result = tx.run("MATCH (start)-[r]->(end) WHERE id(start)=$start and id(end)=$end RETURN r ORDER BY r.bloodycost LIMIT 1", start=start, end=end)
        return result.single()[0]