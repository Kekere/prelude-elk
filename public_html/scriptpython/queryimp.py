from owlready2 import *
import json
import sys

cveid=sys.argv[1]
#cveid="CVE-2005-1794"

class SparqlQueries:
    def __init__(self):
        my_world = World()
        my_world.get_ontology("file:///var/www/html/vdoowl/onto2.owl").load() #path to the owl file is given here
        sync_reasoner(my_world)  #reasoner is started and synchronized here
        self.graph = my_world.as_rdflib_graph()

    def search(self):
        #Search query is given here
        #Base URL of your ontology has to be given here
        query = "base <http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4> " \
        "SELECT DISTINCT ?v ?impmethod ?log " \
        "WHERE {" \
            "?vul <http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#hasIdentity> ?vulid . " \
            "?vulid <http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#value> ?v . " \
            "?vul <http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#hasScenario> ?sce . " \
            "?sce <http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#hasAction> ?ac ." \
            "?sce  <http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#affectsProduct> ?prod ." \
            "?ac <http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#resultsInImpact> ?im ." \
            "?im <http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#hasLogicalImpact> ?log ." \
            "?ac <http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#hasImpactMethod> ?imp ." \
            "?imp <http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#value> ?impmethod ." \
            "FILTER (str(?v) = '"+cveid+"') ." \
        "}"
        #query is being run
        resultsList = self.graph.query(query)
        #creating json object
        response = []
        for item in resultsList:
            s = str(item['v'].toPython())
            s = re.sub(r'.*#', "", s)

            a = str(item['impmethod'].toPython())
            a = re.sub(r'.*#', "", a)

            e = str(item['log'].toPython())
            e = re.sub(r'.*#', "", e)
            response.append({'cve' : s, 'method' : a, 'impact':e})
            #print(item)
            #return item
        print(response) #just to show the output
        return response


runQuery = SparqlQueries()
runQuery.search()