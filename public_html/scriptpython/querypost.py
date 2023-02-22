from owlready2 import *
import json
import sys

cveid=sys.argv[1]
prod=sys.argv[2]
#cveid="CVE-2005-1794"
#prod="windows"

class SparqlQueries:
    def __init__(self):
        my_world = World()
        my_world.get_ontology("file:///var/www/html/vdoowl/onto.owl").load() #path to the owl file is given here
        sync_reasoner(my_world)  #reasoner is started and synchronized here
        self.graph = my_world.as_rdflib_graph()

    def search(self):
        #Search query is given here
        #Base URL of your ontology has to be given here
        query = "base <http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4> " \
        "SELECT DISTINCT ?v ?pos ?priv ?im ?impmethod ?at ?aut ?log ?sce ?cpe ?imp ?priv1 ?priv ?sce1" \
        "WHERE { " \
        "?vul <http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#hasIdentity> ?vulid . " \
        "?vulid <http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#value> ?v . " \
        "?vul <http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#hasScenario> ?sce . " \
        "?sce <http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#hasAction> ?ac ." \
        "?sce  <http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#affectsProduct> ?prod ." \
        "?prod <http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#hasProductEnumeration> ?prodEn ." \
        "?prodEn <http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#values> ?cpe ." \
        "?ac <http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#resultsInImpact> ?im ." \
        "?im <http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#hasLogicalImpact> ?log ." \
        "?ac <http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#hasImpactMethod> ?imp ." \
        "?imp <http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#value> ?impmethod ." \
        "?im <http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#gainedPrivileges> ?priv ." \
        "{" \
        "SELECT ?pos ?at ?aut ?priv1 ?sce1" \
        "WHERE {"\
        "?vl <http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#hasIdentity> ?vulid2 ."\
        "?vl <http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#hasScenario> ?sce1 ." \
        "?vulid2 <http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#value> ?pos ." \
        "?sce1 <http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#hasAction> ?ac1 ." \
        "?sce1 <http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#requiresAttackTheater> ?at ." \
        "?sce1 <http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#blockedByBarrier> ?bar ." \
        "?bar <http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#barrierType> ?aut ." \
        "?bar <http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#neededPrivileges> ?priv1 ." \
        "}" \
        "}" \
        "FILTER (str(?v) = '"+cveid+"') ." \
        "FILTER regex(?cpe, '"+prod+"', 'i')" \
        "}" 
        #query is being run
        resultsList = self.graph.query(query)
        #creating json object
        response = []
        for item in resultsList:
            s = str(item['pos'].toPython())
            s = re.sub(r'.*#',"",s)

            p = str(item['priv'].toPython())
            p = re.sub(r'.*#', "", p)

            o = str(item['impmethod'].toPython())
            o = re.sub(r'.*#', "", o)

            a = str(item['aut'].toPython())
            a = re.sub(r'.*#', "", a)

            e = str(item['at'].toPython())
            e = re.sub(r'.*#', "", e)

            i = str(item['log'].toPython())
            i = re.sub(r'.*#', "", i)

            c = str(item['v'].toPython())
            c = re.sub(r'.*#', "", c)

            x = str(item['priv1'].toPython())
            x = re.sub(r'.*#', "", x)
            response.append({'lastcve': c,'postcondition' : s, 'privilege' : p, 'impactMethod': o, 'barrier': a, 'mean':e, 'impact':i, 'neededPrivileges':x})
            #print(item)
            #return item
        print(response) #just to show the output
        return response


runQuery = SparqlQueries()
runQuery.search()