from owlready2 import *

cveid='CVE-2012-0152'

class SparqlQueries:
	def __init__(self):
		my_world = World()
		my_world.get_ontology("file:///home/keren/prelude-elk/dev/vdoowl/onto.owl").load() #path to the owl file is given here
		sync_reasoner(my_world)  #reasoner is started and synchronized here
		self.graph = my_world.as_rdflib_graph()

	def search(self):
		#Search query is given here
		#Base URL of your ontology has to be given here
		query = "base <http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4> " \
				"ASK " \
				"WHERE { " \
				"?vul <http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#hasIdentity> ?vulid . " \
				"?vul <http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#hasScenario> ?sce ." \
				"?vulid <http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#value> ?v ." \
				"?sce <http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#hasAction> ?ac ." \
				"?ac <http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#resultsInImpact> ?im ." \
				"?im <http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#hasLogicalImpact> <http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#PrivilegeEscalation> ." \
				"FILTER (str(?v) = '"+cveid+"') ." \
				"}"
		
		#query is being run
		resultsList = self.graph.query(query)

		#creating json object
		response = []
		for item in resultsList:
			#s = str(item['log'].toPython())
			#s = re.sub(r'.*#',"",s)

			#p = str(item['v'].toPython())
			#p = re.sub(r'.*#', "", p)

			#o = str(item['vulid'].toPython())
			#o = re.sub(r'.*#', "", o)
			#response.append({'imp' : s})
			print(item)
			return item
		#print(response) #just to show the output
		#return response


runQuery = SparqlQueries()
runQuery.search()
