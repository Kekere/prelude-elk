from rdflib import Graph, Namespace, Literal, URIRef
from rdflib.namespace import RDF, RDFS, OWL

# Load your TTL file into an RDF graph
filename = "play.owl"
path = "" + filename
g = Graph()
g.parse(path, format="ttl")
# Define your custom tag namespace
ns = Namespace("http://kevin.abouahmed/IncidentResponseOntologyPlaybook#")

new_individual_uriplay = URIRef("http://kevin.abouahmed/IncidentResponseOntologyPlaybook#Playbook__CVE-2021-21277")
new_individual_typeplay = URIRef("http://www.w3.org/2002/07/owl#NamedIndividual")
g.add((new_individual_uriplay, RDF.type, new_individual_typeplay))
g.add((new_individual_uriplay, RDF.type, ns.Playbook))
g.add((new_individual_uriplay, RDFS.label, Literal("Playbook : Response to CVE-2021-21277")))
g.add((new_individual_uriplay, ns.has_description, Literal("This playbook is intended to answer the vulnerability identified by the IDCVE-2021-21277")))
new_individual_uri = URIRef("http://kevin.abouahmed/IncidentResponseOntologyPlaybook#Step1_CVE-2021-21277")
new_individual_type = URIRef("http://www.w3.org/2002/07/owl#NamedIndividual")
g.add((new_individual_uriplay, ns.has_coa, new_individual_uri))
new_individual_uri2 = URIRef("http://kevin.abouahmed/IncidentResponseOntologyPlaybook#Step2_CVE-2021-21277")
new_individual_type2 = URIRef("http://www.w3.org/2002/07/owl#NamedIndividual")
g.add((new_individual_uri, RDF.type, new_individual_type))
g.add((new_individual_uri, RDF.type, ns.Playbook_Step))
g.add((new_individual_uri, RDFS.label, Literal("Step1_CVE-2021-21277")))
g.add((new_individual_uri, ns.parallel, new_individual_uri2))
new_individual_uriact=URIRef("http://kevin.abouahmed/IncidentResponseOntologyPlaybook#RA2405")
g.add((new_individual_uri, ns.is_action, new_individual_uriact))

new_individual_uri3=URIRef("http://kevin.abouahmed/IncidentResponseOntologyPlaybook#Step3_CVE-2021-21277")
g.add((new_individual_uri2, RDF.type, new_individual_type2))
g.add((new_individual_uri, RDF.type, ns.Playbook_Step))
g.add((new_individual_uri, RDFS.label, Literal("Step2_CVE-2021-21277")))
g.add((new_individual_uri2, ns.has_next, new_individual_uri3))
new_individual_uriact2=URIRef("http://kevin.abouahmed/IncidentResponseOntologyPlaybook#RA2001")
g.add((new_individual_uri2, ns.is_action, new_individual_uriact2))
# Serialize the modified graph back to TTL format
#with open("play.owl", "wb") as f:
#    f.write(g.serialize(format="ttl"))
# Serialize the modified RDF graph back to TTL
g.serialize(destination=path, format="ttl")
