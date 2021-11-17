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
        bloodycosts = [
            {'cost':0, 'edges':'MemberOf', 'endnode':'Group'},
            {'cost':100, 'edges':'AddMember|GenericAll|GenericWrite|AllExtendedRights', 'endnode':'Group'},
            {'cost':200, 'edges':'WriteDacl|Owns', 'endnode':'Group'},
            {'cost':300, 'edges':'WriteOwner', 'endnode':'Group'},

            {'cost':1, 'edges':'DCSync|GenericAll|GetChangesAll|AllExtendedRights', 'endnode':'Domain'},
            {'cost':101, 'edges':'WriteDacl|Owns', 'endnode':'Domain'},
            {'cost':102, 'edges':'WriteOwner', 'endnode':'Domain'},

            {'cost':100000, 'edges':'GenericAll|ForceChangePassword|AllExtendedRights', 'endnode':'User'},
            {'cost':100001, 'edges':'WriteDacl|Owns', 'endnode':'User'},
            {'cost':100002, 'edges':'WriteOwner', 'endnode':'User'},

            {'cost':100100, 'edges':'GenericAll|ForceChangePassword|AllExtendedRights', 'endnode':'Computer'},
            {'cost':100101, 'edges':'WriteDacl|Owns', 'endnode':'Computer'},
            {'cost':100102, 'edges':'WriteOwner', 'endnode':'Computer'}

            # TODO: Maybe take into account path with GenericAll on GPO
            # TODO: Maybe take into account path with GenericAll on OU
        ]

        for bloodycost in bloodycosts:
            tx.run(f"MATCH ()-[r:{bloodycost.edges}]->(:{bloodycost.endnode}) SET r.bloodycost = {bloodycost.cost}")

    # Alternative with only CYPHER https://liberation-data.com/saxeburg-series/2018/11/28/rock-n-roll-traffic-routing.html
    # CONS: Less efficient, more complex PROS: Doesn't need GDS plugin
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
    
    # @staticmethod
    # def _retrieveCheaperEdge(tx, start, end):
    #     result = tx.run("MATCH (start)-[r]->(end) WHERE id(start)=$start and id(end)=$end RETURN r ORDER BY r.bloodycost LIMIT 1", start=start, end=end)
    #     return result.single()[0]