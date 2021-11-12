import argparse, json
from autobloody import database

def main():
    parser = argparse.ArgumentParser(description='Active Directory Privilege Escalation Framework', formatter_class=argparse.RawTextHelpFormatter)

    # DB parameters
    parser.add_argument("--dburi", default="bolt://localhost:7687", help="The host neo4j is running on. Default: localhost.")
    parser.add_argument("-du", "--dbuser", default="neo4j", help="Neo4j username to use")
    parser.add_argument("-dp", "--dbpassword", help="Neo4j password to use", required=True)
    parser.add_argument("-ds", "--dbsource", help="Label of the source node", required=True)
    parser.add_argument("-dt", "--dbtarget", help="Label of the target node", required=True)
    parser.add_argument("-f", "--filepath", help="File path for the graph path file (default is path.json)", default="path.json")


    args = parser.parse_args()
    db = database.Database(args.dburi, args.dbuser, args.dbpassword)
    path = db.getPrivescPath(args.dbsource, args.dbtarget)
    jsonable_path = []
    for rel in path:
        start_node = {'name':rel.start_node['name'], 'distinguishedname':rel.start_node['distinguishedname'], 'objectid':rel.start_node['objectid']}
        end_node = {'name':rel.end_node['name'], 'distinguishedname':rel.end_node['distinguishedname'], 'objectid': rel.end_node['objectid']}
        jsonable_path.append({'start_node':start_node, 'end_node':end_node, 'cost':rel['cost']})

    with open(args.filepath, 'w+') as f:
        json.dump(jsonable_path, f)
    db.close()

if __name__ == '__main__':
    main()