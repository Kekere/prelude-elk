from owlready2 import *
import json
import sys

cveid=sys.argv[1]
prod=sys.argv[2]

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
				"SELECT DISTINCT ?val ?priv " \
				"WHERE { " \
				"?vl <http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#hasIdentity> ?postcondition . " \
				"?vl <http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#hasScenario> ?sce1 ." \
                "?postcondition <http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#value> ?val ."\
				"?sce1 <http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#affectsProduct> ?prod ." \
				"?sce1 <http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#blockedByBarrier> ?bar ." \
				"?bar <http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#neededPrivileges> ?priv ." \
                "?prod <http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#hasProductEnumeration> ?prodEn ." \
                "?prodEn <http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#values> ?cpe ." \
				"{" \
                "SELECT ?priv ?v" \
                "WHERE {" \
                "?vul <http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#hasIdentity> ?vulid ." \
                "?vul <http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#hasScenario> ?sce ." \
                "?vulid <http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#value> ?v ." \
                "?sce <http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#hasAction> ?ac ." \
                "?ac <http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#resultsInImpact> ?im ." \
				"?im <http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#gainedPrivileges> ?priv ." \
                "FILTER (str(?v) = '"+cveid+"') ." \
                "}" \
                "}" \
                "FILTER regex(?cpe, '"+prod+"', 'i')" \
                "}"


		#query is being run
		resultsList = self.graph.query(query)

		#creating json object
		response = []
		for item in resultsList:
			s = str(item['val'].toPython())
			s = re.sub(r'.*#',"",s)

			p = str(item['priv'].toPython())
			p = re.sub(r'.*#', "", p)

			#o = str(item['vulid'].toPython())
			#o = re.sub(r'.*#', "", o)
			response.append({'postcondition' : s, 'privilege' : p})
			#print(item)
			#return item
		print(response) #just to show the output
		return response


runQuery = SparqlQueries()
runQuery.search()