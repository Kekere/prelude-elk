import time
import json
#SPARQL Query to the Playbook Standardisation Ontology
from owlready2 import *
# importing csv library
import csv
import pandas as pd
import csv
import ast
#from os import listxattr
import json
from paretoset import paretoset
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from rdflib import Graph, Namespace, Literal, URIRef
from rdflib.namespace import RDF, RDFS, OWL
import rdflib
import ast
import graphmatch
def searchactiond(id):
    action=[]
    sparql = """select ?l where{
                      ?action <http://kevin.abouahmed/IncidentResponseOntologyPlaybook#react-id> '"""+id+"""' .
                      ?action <http://www.w3.org/2000/01/rdf-schema#label> ?l.
                      ?action <http://kevin.abouahmed/IncidentResponseOntologyPlaybook#performed_by> ?command .
                      ?command <http://kevin.abouahmed/IncidentResponseOntologyPlaybook#executed_by> ?tool .
                }"""
    #query is being run
    resultsList = graph.query(sparql)
    for row in resultsList:
        s = str(row['l'].toPython())
        action.append(s)
    return action

my_world = World()
my_world.get_ontology("/var/www/html/ADG/playbook.owl").load() #path to the owl file is given here
#sync_reasoner(my_world)  #reasoner is started and synchronized here
graph = my_world.as_rdflib_graph()

def searchaction(id):
    action=[]
    sparql = """select ?l ?impact ?loss ?complexity ?rl where{
                      ?action <http://kevin.abouahmed/IncidentResponseOntologyPlaybook#react-id> '"""+id+"""' .
                      ?action <http://www.w3.org/2000/01/rdf-schema#label> ?l.
                      ?action <http://kevin.abouahmed/IncidentResponseOntologyPlaybook#has_impact_score> ?impact.
                      ?action <http://kevin.abouahmed/IncidentResponseOntologyPlaybook#generatesLoss> ?loss.
                      ?action <http://kevin.abouahmed/IncidentResponseOntologyPlaybook#has_complexity_level> ?complexity.
                      ?action <http://kevin.abouahmed/IncidentResponseOntologyPlaybook#has_requirement> ?r.
                      ?r <http://www.w3.org/2000/01/rdf-schema#label> ?rl.
                }"""
    #query is being run
    resultsList = graph.query(sparql)
    requirement=[]
    for row in resultsList:
        s = str(row['l'].toPython())
        impact=int(row['impact'].toPython())
        complexity=int(row['complexity'].toPython())
        loss=float(row['loss'].toPython())
        requirement.append(str(row['rl'].toPython()))
        if requirement not in action:
          action.append(s)
          action.append(impact)
          action.append(complexity)
          action.append(loss)
          action.append(requirement)
    return action

def compare_lists(list1, list2):
    for item in list1:
        if item in list2:
            return True
    return False

def searchid(action):
    reactid=[]
    sparql = """select ?id where{
                      ?action <http://kevin.abouahmed/IncidentResponseOntologyPlaybook#react-id> ?id .
                      ?action <http://www.w3.org/2000/01/rdf-schema#label> '"""+action+"""' .
                }"""
    #query is being run
    resultsList = graph.query(sparql)
    for row in resultsList:
        s = str(row['id'].toPython())
        #reactid.append(s)
    return s
def has_duplicate_phase(actions):
    phases = set()

    for action in actions:
        phase = action.get('phase')

        if phase is not None:
            if phase in phases:
                return True
            else:
                phases.add(phase)
def find_combinations(data, target_sum, current_combination=[]):
    combinations = []

    for i, item in enumerate(data):
        if item['complexity'] == target_sum:
            #print(target_sum, item['action'])
            combinations.append(current_combination + [item])
        elif item['complexity'] < target_sum:
            #print(target_sum, item['score'])
            remaining_data = data[i + 1:]
            new_combination = current_combination + [item]
            new_target_sum = target_sum - item['complexity']
            #print(new_target_sum,target_sum, item['score'])
            sub_combinations = find_combinations(remaining_data, new_target_sum, new_combination)
            combinations.extend(sub_combinations)

    return combinations
def calculate_impact_sum(json_object):
    return sum(item.get('impact', 0) for item in json_object)
def calculate_complexity_sum(json_object):
    return sum(item.get('complexity', 0) for item in json_object)
def calculate_loss_sum(json_object):
    return sum(item.get('loss', 0) for item in json_object)

def recovery(action):
  actions=[]
  sparql = """select ?l where{
                    ?action <http://www.w3.org/2000/01/rdf-schema#label> '"""+action+"""'.
                    ?action <http://kevin.abouahmed/IncidentResponseOntologyPlaybook#is_linked_to_recovery_action> ?idrec .
                    ?idrec <http://www.w3.org/2000/01/rdf-schema#label> ?l .
              }"""
  #query is being run
  resultsList = graph.query(sparql)
  for row in resultsList:
      recovact=str(row['l'].toPython())
      actions.append(recovact)
  return actions
def char(id, cat):
    action={}
    sparql = """select ?action ?impact ?loss ?complexity ?rl where{
                      ?action <http://www.w3.org/2000/01/rdf-schema#label> '"""+id+"""'.
                      ?action <http://kevin.abouahmed/IncidentResponseOntologyPlaybook#has_impact_score> ?impact.
                      ?action <http://kevin.abouahmed/IncidentResponseOntologyPlaybook#generatesLoss> ?loss.
                      ?action <http://kevin.abouahmed/IncidentResponseOntologyPlaybook#has_complexity_level> ?complexity.
                }"""
    #query is being run
    resultsList = graph.query(sparql)
    for row in resultsList:
        impact=int(row['impact'].toPython())
        complexity=int(row['complexity'].toPython())
        loss=float(row['loss'].toPython())
        action={'action':id,'impact':impact,'complexity':complexity,'loss':loss,'phase':int(5), 'category':int(cat)}
    return action
def less(id, cat):
    action={}
    sparql = """select ?action ?impact ?loss ?complexity ?rl where{
                      ?action <http://www.w3.org/2000/01/rdf-schema#label> '"""+id+"""'.
                      ?action <http://kevin.abouahmed/IncidentResponseOntologyPlaybook#has_impact_score> ?impact.
                      ?action <http://kevin.abouahmed/IncidentResponseOntologyPlaybook#generatesLoss> ?loss.
                      ?action <http://kevin.abouahmed/IncidentResponseOntologyPlaybook#has_complexity_level> ?complexity.
                }"""
    #query is being run
    resultsList = graph.query(sparql)
    for row in resultsList:
        impact=int(row['impact'].toPython())
        complexity=int(row['complexity'].toPython())
        loss=float(row['loss'].toPython())
        action={'action':id,'impact':impact,'complexity':complexity,'loss':loss,'phase':int(6), 'category':cat}
    return action

# Function to calculate the total impact for a given item
def calculate_total_impact(item):
    return sum(action['impact'] for action in item)
def tsv_to_list(tsv_file, column_index):
    result = []
    with open(tsv_file, 'r', newline='', encoding='utf-8') as file:
        reader = csv.reader(file, delimiter='\t')
        for row in reader:
            # Ensure the column index is within the range of the row
            if column_index < len(row):
                # Convert the string representation of a list to an actual list
                try:
                    value_list = ast.literal_eval(row[column_index])
                    result.append(value_list)
                except (SyntaxError, ValueError):
                    print(f"Error: Unable to convert string to list in row {reader.line_num}, column {column_index}")

    return result
#A modifier
def playbook(cve, lst, listaction, listrequirement, listimpact, listcomplexity, listloss, listphase, listcategory):
  df = pd.DataFrame(list(zip(lst, listaction, listrequirement, listimpact, listcomplexity, listloss, listphase, listcategory)),
                columns =['CVE ID', 'Action', 'Requirement', 'Impact', 'Complexity', 'Loss', 'Phase', 'Category'])
  #print(df)
  df.to_csv('/var/www/html/ADG/actions.tsv', encoding='utf-8', sep='\t')

  listtsv=[]
  with open("/var/www/html/ADG/actions.tsv") as file:
      tsv_file = csv.reader(file, delimiter="\t")
      for line in tsv_file:
          listtsv.append(line)

  # Example usage
  tsv_file_path = '/var/www/html/ADG/actions.tsv'
  column_to_convert = 3  # Change this to the index of the column containing the list

  resulting_lists = tsv_to_list(tsv_file_path, column_to_convert)

  # Python program to read
  # json file
  #A modifier pour prendre en compte les equipements et softwares de la vulnérabilité en question
  # Opening JSON file
  f = open('/var/www/html/ADG/systems.json')

  # returns JSON object as
  # a dictionary
  equipements=[]
  softwares=[]
  data = json.load(f)
  cve_desc = open("/var/www/html/ADG/"+cve+'.json')
  #print(len(actionlist))
  cve_data=json.load(cve_desc)
  for i in data:
    equipements.append(i)
    if cve_data['Equipement'].lower()==i.lower():
      softwares.append(data[i])
      print(data[i])
  print(equipements)
  print(softwares)

  # Closing file
  f.close()

  tsv_data = pd.read_csv('/var/www/html/ADG/actions.tsv', sep='\t')

  actionlist=[]
  impactlist=[]
  complexitylist=[]
  losslist=[]
  phaselist=[]
  categorylist=[]
  for t in listtsv:
    # Convert the string to a list using ast.literal_eval
    try:
        output_list = ast.literal_eval(t[3])
        listcomp=compare_lists(output_list,equipements)
        if listcomp:
          #print(t[3])
          actionlist.append(t[2])
          impactlist.append(int(t[4]))
          complexitylist.append(int(t[5]))
          losslist.append(float(t[6]))
          phaselist.append(int(t[7]))
          categorylist.append(int(t[8]))
        else:
          for s in softwares:
            listcomp2=compare_lists(output_list,s)
            if listcomp2:
                actionlist.append(t[2])
                impactlist.append(int(t[4]))
                complexitylist.append(int(t[5]))
                losslist.append(float(t[6]))
                phaselist.append(int(t[7]))
                categorylist.append(int(t[8]))
    except (SyntaxError, ValueError) as e:
        print(f"Error: {e}")

  # Opening JSON file
  attack = open("/var/www/html/ADG/"+cve+'.json')
  #print(len(actionlist))
  datat=json.load(attack)
  #print(datat['Position'])
  #localsyn=['local','internal']
  #remotesyn=['remote','external']
  # Closing file
  res=[]
  resimpact=[]
  if datat['Position']=='local':
      res = list(filter(lambda x: 'external' not in x, actionlist))
      res=list(filter(lambda x: 'domain' not in x, res))

  if datat['Position']=='remote':
      res = list(filter(lambda x: 'internal' not in x, actionlist))
      #print(res)
  #print(len(res))
  #print(len(res))
  ply=[]
  newlist=[]
  phase=[]
  comp=[]
  los=[]
  cat=[]
  print('ok')
  print(actionlist)
  print(res)
  for r in actionlist:
    if r in res:
      idx=actionlist.index(r)
      ply.append(impactlist[idx])
      comp.append(complexitylist[idx])
      los.append(losslist[idx])
      phase.append(phaselist[idx])
      cat.append(categorylist[idx])
  #impactlist.sort(reverse=True)
  newlist=[{'action': action, 'impact': impact, 'complexity':complexity, 'loss':loss, 'phase':phase, 'category':cat} for action, impact, complexity, loss, phase, cat in zip(res, ply, comp, los, phase, cat)]
  playbook= sorted(newlist, key=lambda k: (int(k['phase']),-int(k["impact"])))
  playbook=list(filter(lambda x: 5!=x['phase'], playbook))
  if len(playbook)!=0:
    #playbookrec=list(filter(lambda x: 5==x['phase'], playbook))

    #target_sum = 10  # Change this to the desired sum
    playbooks=[]
    if has_duplicate_phase(playbook):
      data = playbook
      print(data)
      # Grouper les données par 'phase' et 'category'
      phase_category_groups = {}
      for item in data:
          phase_category = (item['phase'], item['category'])
          if phase_category not in phase_category_groups:
              phase_category_groups[phase_category] = []
          phase_category_groups[phase_category].append(item)
      # Générer toutes les combinaisons possibles
      combinations = []
      for r in range(2, min(len(playbook) + 1, 8)):  # Générer des combinaisons de 2 à n éléments
          for combination in itertools.combinations(data, r):
              unique_phases = set(item['phase'] for item in combination)
              if len(unique_phases) >= 2:
                # Vérifier qu'il n'y a qu'une seule répétition pour chaque valeur de 'category' pour une même 'phase'
                unique_categories = set((item['phase'], item['category']) for item in combination)
                if len(unique_categories) == len(combination):
                    # Vérifier que la somme d''impact' pour chaque combinaison est supérieure à 5
                    if sum(item['impact'] for item in combination) > 5:
                        combinations.append(combination)

      # Print the result
      playbooks=[]
      for combination in combinations:
          play=[]
          for e in combination:
            play.append(e)
          playbooks.append(play)
      sommeimpact=[]
      sommecomplexite=[]
      sommeperte=[]
      for i, json_object in enumerate(playbooks, start=1):
          sum_score = calculate_impact_sum(json_object)
          sum_time=calculate_complexity_sum(json_object)
          sum_loss=calculate_loss_sum(json_object)
          sommecomplexite.append(sum_time)
          sommeimpact.append(sum_score)
          sommeperte.append(100*sum_loss)
          #print(f"Sum of 'score' for JSON object {i}: {sum_score}")
      plays = pd.DataFrame({"impact": sommeimpact,"complexity": sommecomplexite, "loss": sommeperte})
      mask = paretoset(plays, sense=["max", "min", "min"])
      paretoset_plays = plays[mask]
      print(len(plays),len(paretoset_plays))
      #print(paretoset_plays)
    else:
        playbooks.append(playbook)
    #print(len(playbooks))

    if len(playbooks)>1:
      playbookcandidat=[]
      #print(len(playbooks))
      for i in range(len(paretoset_plays)):
        #print(paretoset_plays.index[i])
        playbookcandidat.append(playbooks[paretoset_plays.index[i]])
      #print(playbookcandidat)
      #print(len(playbookcandidat))
      playbooks=[]
      for e in playbookcandidat:
        for i in e:
          if i['phase']==3:
            action=i['action']
            category=i['category']
            recoveryactions=recovery(action)
            if len(recoveryactions)!=0:
              for o in recoveryactions:
                e.append(char(o,category))
        if less('develop incident report',0) not in e:
          e.append(less('develop incident report',0))
        if less('conduct lessons learned exercise',0) not in e:
          e.append(less('conduct lessons learned exercise',0))
        playbooks.append(e)
    if len(playbooks)!=0:
      # Find the item with the highest total impact
      max_impact_item = max(playbooks, key=lambda x: calculate_total_impact(x))

      print("Item with the highest total impact:")
      print(max_impact_item)
      for x in playbooks:
        print(x)
      #SPARQL Query to the Playbook Standardisation Ontology
      my_world = World()
      my_world.get_ontology("/var/www/html/ADG/playbook.owl").load() #path to the owl file is given here
      #sync_reasoner(my_world)  #reasoner is started and synchronized here
      graph = my_world.as_rdflib_graph()

      # Load your TTL file into an RDF graph
      filename = "/var/www/html/ADG/play.owl"
      path = "" + filename
      g = Graph()
      g.parse(path, format="ttl")

      # Define your custom tag namespace
      ns = Namespace("http://kevin.abouahmed/IncidentResponseOntologyPlaybook#")
      playbookname="Playbook_"+cve
      for i in range(len(max_impact_item)):
          if i==0:
            action_Step1=max_impact_item[i]['action']
            phase1=max_impact_item[i]['phase']
            category1=max_impact_item[i]['category']
            reactid1=searchid(action_Step1)
            step1name="Step1_"+cve
            new_individual_uriplay = URIRef("http://kevin.abouahmed/IncidentResponseOntologyPlaybook#"+playbookname)
            new_individual_typeplay = URIRef("http://www.w3.org/2002/07/owl#NamedIndividual")
            g.add((new_individual_uriplay, RDF.type, new_individual_typeplay))
            g.add((new_individual_uriplay, RDF.type, ns.Playbook))
            new_individual_uri = URIRef("http://kevin.abouahmed/IncidentResponseOntologyPlaybook#"+step1name)
            new_individual_type = URIRef("http://www.w3.org/2002/07/owl#NamedIndividual")
            g.add((new_individual_uriplay, RDFS.label, Literal("Playbook : Response to "+cve)))
            g.add((new_individual_uriplay, ns.has_description, Literal("This playbook is intended to answer the vulnerability identified by the ID "+cve)))
            g.add((new_individual_uriplay, ns.has_coa, new_individual_uri))
            playbook1='<owl:NamedIndividual rdf:about="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+playbookname+'">\n<rdf:type rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#Playbook"/>\n<IncidentResponseOntologyPlaybook:has_coa rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+step1name+'"/>\n<IncidentResponseOntologyPlaybook:has_description>This playbook is intended to answer the vulnerability identified by the ID'+cve+'</IncidentResponseOntologyPlaybook:has_description>\n<rdfs:label>Playbook : Response to '+cve+'</rdfs:label>\n</owl:NamedIndividual>'
          if i==1:
            if phase1!=max_impact_item[i]['phase']:
              action_Step2=max_impact_item[i]['action']
              phase2=max_impact_item[i]['phase']
              category2=max_impact_item[i]['category']
              reactid2=searchid(action_Step2)
              step2name="Step2_"+cve
              new_individual_uri2 = URIRef("http://kevin.abouahmed/IncidentResponseOntologyPlaybook#"+step2name)
              new_individual_type2 = URIRef("http://www.w3.org/2002/07/owl#NamedIndividual")
              g.add((new_individual_uri, RDF.type, new_individual_type))
              g.add((new_individual_uri, RDF.type, ns.Playbook_Step))
              g.add((new_individual_uri, RDFS.label, Literal(str(step1name))))
              g.add((new_individual_uri, ns.has_next, new_individual_uri2))
              new_individual_uriact=URIRef("http://kevin.abouahmed/IncidentResponseOntologyPlaybook#"+reactid1)
              g.add((new_individual_uri, ns.is_action, new_individual_uriact))
              playbook2='<owl:NamedIndividual rdf:about="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+step1name+'">\n<rdf:type rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#Playbook_Step"/>\n<IncidentResponseOntologyPlaybook:has_next rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+step2name+'"/>\n<IncidentResponseOntologyPlaybook:is_action rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+reactid1+'"/>\n<rdfs:label>'+step1name+'</rdfs:label></owl:NamedIndividual>'
            else:
              if category1!=max_impact_item[i]['category']:
                action_Step2=max_impact_item[i]['action']
                phase2=max_impact_item[i]['phase']
                reactid2=searchid(action_Step2)
                step2name="Step2_"+cve
                action_Step2=max_impact_item[i]['action']
                phase2=max_impact_item[i]['phase']
                category2=max_impact_item[i]['category']
                reactid2=searchid(action_Step2)
                step2name="Step2_"+cve
                new_individual_uri2 = URIRef("http://kevin.abouahmed/IncidentResponseOntologyPlaybook#"+step2name)
                new_individual_type2 = URIRef("http://www.w3.org/2002/07/owl#NamedIndividual")
                g.add((new_individual_uri, RDF.type, new_individual_type))
                g.add((new_individual_uri, RDF.type, ns.Playbook_Step))
                g.add((new_individual_uri, RDFS.label, Literal(str(step1name))))
                g.add((new_individual_uri, ns.parallel, new_individual_uri2))
                new_individual_uriact=URIRef("http://kevin.abouahmed/IncidentResponseOntologyPlaybook#"+reactid1)
                g.add((new_individual_uri, ns.is_action, new_individual_uriact))

                g.add((new_individual_uri2, RDF.type, new_individual_type2))
                g.add((new_individual_uri2, RDF.type, ns.Playbook_Step))
                g.add((new_individual_uri2, RDFS.label, Literal(str(step2name))))
                new_individual_uriact2=URIRef("http://kevin.abouahmed/IncidentResponseOntologyPlaybook#"+reactid2)
                g.add((new_individual_uri2, ns.is_action, new_individual_uriact2))
                playbook2='<owl:NamedIndividual rdf:about="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+step1name+'">\n<rdf:type rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#Playbook_Step"/>\n<IncidentResponseOntologyPlaybook:parallel rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+step2name+'"/>\n<IncidentResponseOntologyPlaybook:is_action rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+reactid1+'"/>\n<rdfs:label>'+step1name+'</rdfs:label></owl:NamedIndividual>'
                playbook2_2='<owl:NamedIndividual rdf:about="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+step2name+'">\n<rdf:type rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#Playbook_Step"/>\n<IncidentResponseOntologyPlaybook:is_action rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+reactid2+'"/>\n<rdfs:label>'+step2name+'</rdfs:label>\n</owl:NamedIndividual>'
              else:
                action_Step2=max_impact_item[i]['action']
                phase2=max_impact_item[i]['phase']
                category2=max_impact_item[i]['category']
                reactid2=searchid(action_Step2)
                step2name="Step2_"+cve
                new_individual_uri2 = URIRef("http://kevin.abouahmed/IncidentResponseOntologyPlaybook#"+step2name)
                new_individual_type2 = URIRef("http://www.w3.org/2002/07/owl#NamedIndividual")
                g.add((new_individual_uri, RDF.type, new_individual_type))
                g.add((new_individual_uri, RDF.type, ns.Playbook_Step))
                g.add((new_individual_uri, RDFS.label, Literal(str(step1name))))
                g.add((new_individual_uri, ns.has_next, new_individual_uri2))
                new_individual_uriact=URIRef("http://kevin.abouahmed/IncidentResponseOntologyPlaybook#"+reactid1)
                g.add((new_individual_uri, ns.is_action, new_individual_uriact))
                playbook2='<owl:NamedIndividual rdf:about="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+step1name+'">\n<rdf:type rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#Playbook_Step"/>\n<IncidentResponseOntologyPlaybook:has_next rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+step2name+'"/>\n<IncidentResponseOntologyPlaybook:is_action rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+reactid1+'"/>\n<rdfs:label>'+step1name+'</rdfs:label></owl:NamedIndividual>'
                #playbook3_2='<owl:NamedIndividual rdf:about="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+step3name+'">\n<rdf:type rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#Playbook_Step"/>\n<IncidentResponseOntologyPlaybook:is_action rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+reactid3+'"/>\n<rdfs:label>'+step3name+'</rdfs:label>\n</owl:NamedIndividual>'
          if i==2:
            if phase2!=max_impact_item[i]['phase']:
              action_Step3=max_impact_item[i]['action']
              phase3=max_impact_item[i]['phase']
              category3=max_impact_item[i]['category']
              reactid3=searchid(action_Step3)
              step3name="Step3_"+cve
              new_individual_uri3 = URIRef("http://kevin.abouahmed/IncidentResponseOntologyPlaybook#"+step3name)
              new_individual_type3 = URIRef("http://www.w3.org/2002/07/owl#NamedIndividual")
              g.add((new_individual_uri2, RDF.type, new_individual_type2))
              g.add((new_individual_uri2, RDF.type, ns.Playbook_Step))
              g.add((new_individual_uri2, RDFS.label, Literal(str(step2name))))
              g.add((new_individual_uri2, ns.has_next, new_individual_uri3))
              new_individual_uriact2=URIRef("http://kevin.abouahmed/IncidentResponseOntologyPlaybook#"+reactid2)
              g.add((new_individual_uri2, ns.is_action, new_individual_uriact2))
              playbook3='<owl:NamedIndividual rdf:about="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+step2name+'">\n<rdf:type rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#Playbook_Step"/>\n<IncidentResponseOntologyPlaybook:has_next rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+step3name+'"/>\n<IncidentResponseOntologyPlaybook:is_action rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+reactid2+'"/>\n<rdfs:label>'+step2name+'</rdfs:label></owl:NamedIndividual>'
            else:
              if category2!=max_impact_item[i]['category']:
                action_Step3=max_impact_item[i]['action']
                phase3=max_impact_item[i]['phase']
                category3=max_impact_item[i]['category']
                print(category3)
                reactid3=searchid(action_Step3)
                step3name="Step3_"+cve
                new_individual_uri3 = URIRef("http://kevin.abouahmed/IncidentResponseOntologyPlaybook#"+step3name)
                new_individual_type3 = URIRef("http://www.w3.org/2002/07/owl#NamedIndividual")
                g.add((new_individual_uri2, RDF.type, new_individual_type))
                g.add((new_individual_uri2, RDF.type, ns.Playbook_Step))
                g.add((new_individual_uri2, RDFS.label, Literal(str(step2name))))
                g.add((new_individual_uri2, ns.parallel, new_individual_uri3))
                new_individual_uriact2=URIRef("http://kevin.abouahmed/IncidentResponseOntologyPlaybook#"+reactid2)
                g.add((new_individual_uri2, ns.is_action, new_individual_uriact2))

                g.add((new_individual_uri3, RDF.type, new_individual_type3))
                g.add((new_individual_uri3, RDF.type, ns.Playbook_Step))
                g.add((new_individual_uri3, RDFS.label, Literal(str(step3name))))
                new_individual_uriact3=URIRef("http://kevin.abouahmed/IncidentResponseOntologyPlaybook#"+reactid3)
                g.add((new_individual_uri3, ns.is_action, new_individual_uriact3))
                playbook3='<owl:NamedIndividual rdf:about="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+step2name+'">\n<rdf:type rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#Playbook_Step"/>\n<IncidentResponseOntologyPlaybook:parallel rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+step3name+'"/>\n<IncidentResponseOntologyPlaybook:is_action rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+reactid2+'"/>\n<rdfs:label>'+step2name+'</rdfs:label></owl:NamedIndividual>'
                playbook3_2='<owl:NamedIndividual rdf:about="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+step3name+'">\n<rdf:type rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#Playbook_Step"/>\n<IncidentResponseOntologyPlaybook:is_action rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+reactid3+'"/>\n<rdfs:label>'+step3name+'</rdfs:label>\n</owl:NamedIndividual>'
              else:
                action_Step3=max_impact_item[i]['action']
                phase3=max_impact_item[i]['phase']
                category3=max_impact_item[i]['category']
                reactid3=searchid(action_Step3)
                step3name="Step3_"+cve
                new_individual_uri3 = URIRef("http://kevin.abouahmed/IncidentResponseOntologyPlaybook#"+step3name)
                new_individual_type3 = URIRef("http://www.w3.org/2002/07/owl#NamedIndividual")
                g.add((new_individual_uri2, RDF.type, new_individual_type))
                g.add((new_individual_uri2, RDF.type, ns.Playbook_Step))
                g.add((new_individual_uri2, RDFS.label, Literal(str(step2name))))
                g.add((new_individual_uri2, ns.has_next, new_individual_uri3))
                new_individual_uriact2=URIRef("http://kevin.abouahmed/IncidentResponseOntologyPlaybook#"+reactid2)
                g.add((new_individual_uri2, ns.is_action, new_individual_uriact2))
                playbook3='<owl:NamedIndividual rdf:about="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+step2name+'">\n<rdf:type rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#Playbook_Step"/>\n<IncidentResponseOntologyPlaybook:has_next rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+step3name+'"/>\n<IncidentResponseOntologyPlaybook:is_action rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+reactid2+'"/>\n<rdfs:label>'+step2name+'</rdfs:label></owl:NamedIndividual>'
                #playbook3_2='<owl:NamedIndividual rdf:about="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+step3name+'">\n<rdf:type rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#Playbook_Step"/>\n<IncidentResponseOntologyPlaybook:is_action rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+reactid3+'"/>\n<rdfs:label>'+step3name+'</rdfs:label>\n</owl:NamedIndividual>'
          if i==3:
            if phase3!=max_impact_item[i]['phase']:
              action_Step4=max_impact_item[i]['action']
              phase4=max_impact_item[i]['phase']
              category4=max_impact_item[i]['category']
              reactid4=searchid(action_Step4)
              step4name="Step4_"+cve
              new_individual_uri4 = URIRef("http://kevin.abouahmed/IncidentResponseOntologyPlaybook#"+step4name)
              new_individual_type4 = URIRef("http://www.w3.org/2002/07/owl#NamedIndividual")
              g.add((new_individual_uri3, RDF.type, new_individual_type3))
              g.add((new_individual_uri3, RDF.type, ns.Playbook_Step))
              g.add((new_individual_uri3, RDFS.label, Literal(str(step3name))))
              g.add((new_individual_uri3, ns.has_next, new_individual_uri4))
              new_individual_uriact3=URIRef("http://kevin.abouahmed/IncidentResponseOntologyPlaybook#"+reactid3)
              g.add((new_individual_uri3, ns.is_action, new_individual_uriact3))
              playbook4='<owl:NamedIndividual rdf:about="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+step3name+'">\n<rdf:type rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#Playbook_Step"/>\n<IncidentResponseOntologyPlaybook:has_next rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+step4name+'"/>\n<IncidentResponseOntologyPlaybook:is_action rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+reactid3+'"/>\n<rdfs:label>'+step3name+'</rdfs:label></owl:NamedIndividual>'
            else:
              if category3!=max_impact_item[i]['category']:
                action_Step4=max_impact_item[i]['action']
                phase4=max_impact_item[i]['phase']
                reactid4=searchid(action_Step4)
                step4name="Step4_"+cve
                new_individual_uri4 = URIRef("http://kevin.abouahmed/IncidentResponseOntologyPlaybook#"+step4name)
                new_individual_type4 = URIRef("http://www.w3.org/2002/07/owl#NamedIndividual")
                g.add((new_individual_uri3, RDF.type, new_individual_type3))
                g.add((new_individual_uri3, RDF.type, ns.Playbook_Step))
                g.add((new_individual_uri3, RDFS.label, Literal(str(step3name))))
                g.add((new_individual_uri3, ns.parallel, new_individual_uri4))
                new_individual_uriact3=URIRef("http://kevin.abouahmed/IncidentResponseOntologyPlaybook#"+reactid3)
                g.add((new_individual_uri3, ns.is_action, new_individual_uriact3))

                g.add((new_individual_uri4, RDF.type, new_individual_type4))
                g.add((new_individual_uri4, RDF.type, ns.Playbook_Step))
                g.add((new_individual_uri4, RDFS.label, Literal(str(step4name))))
                new_individual_uriact4=URIRef("http://kevin.abouahmed/IncidentResponseOntologyPlaybook#"+reactid4)
                g.add((new_individual_uri4, ns.is_action, new_individual_uriact4))
                playbook4='<owl:NamedIndividual rdf:about="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+step3name+'">\n<rdf:type rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#Playbook_Step"/>\n<IncidentResponseOntologyPlaybook:parallel rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+step4name+'"/>\n<IncidentResponseOntologyPlaybook:is_action rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+reactid3+'"/>\n<rdfs:label>'+step3name+'</rdfs:label></owl:NamedIndividual>'
                playbook4_2='<owl:NamedIndividual rdf:about="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+step4name+'">\n<rdf:type rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#Playbook_Step"/>\n<IncidentResponseOntologyPlaybook:is_action rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+reactid4+'"/>\n<rdfs:label>'+step4name+'</rdfs:label>\n</owl:NamedIndividual>'
              else:
                if i!=len(max_impact_item)-1:
                  action_Step4=max_impact_item[i]['action']
                  phase4=max_impact_item[i]['phase']
                  category4=max_impact_item[i]['category']
                  reactid4=searchid(action_Step4)
                  step4name="Step4_"+cve
                  new_individual_uri4 = URIRef("http://kevin.abouahmed/IncidentResponseOntologyPlaybook#"+step4name)
                  new_individual_type4 = URIRef("http://www.w3.org/2002/07/owl#NamedIndividual")
                  g.add((new_individual_uri3, RDF.type, new_individual_type3))
                  g.add((new_individual_uri3, RDF.type, ns.Playbook_Step))
                  g.add((new_individual_uri3, RDFS.label, Literal(str(step3name))))
                  g.add((new_individual_uri3, ns.has_next, new_individual_uri4))
                  new_individual_uriact3=URIRef("http://kevin.abouahmed/IncidentResponseOntologyPlaybook#"+reactid3)
                  g.add((new_individual_uri3, ns.is_action, new_individual_uriact3))
                  playbook4='<owl:NamedIndividual rdf:about="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+step3name+'">\n<rdf:type rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#Playbook_Step"/>\n<IncidentResponseOntologyPlaybook:has_next rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+step4name+'"/>\n<IncidentResponseOntologyPlaybook:is_action rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+reactid3+'"/>\n<rdfs:label>'+step3name+'</rdfs:label></owl:NamedIndividual>'
                  #playbook4_2='<owl:NamedIndividual rdf:about="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+step4name+'">\n<rdf:type rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#Playbook_Step"/>\n<IncidentResponseOntologyPlaybook:is_action rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+reactid4+'"/>\n<rdfs:label>'+step4name+'</rdfs:label>\n</owl:NamedIndividual>'
                else:
                    action_Step4=max_impact_item[i]['action']
                    phase4=max_impact_item[i]['phase']
                    category4=max_impact_item[i]['category']
                    reactid4=searchid(action_Step4)
                    step4name="Step4_"+cve
                    new_individual_uri4 = URIRef("http://kevin.abouahmed/IncidentResponseOntologyPlaybook#"+step4name)
                    new_individual_type4 = URIRef("http://www.w3.org/2002/07/owl#NamedIndividual")
                    g.add((new_individual_uri3, RDF.type, new_individual_type3))
                    g.add((new_individual_uri3, RDF.type, ns.Playbook_Step))
                    g.add((new_individual_uri3, RDFS.label, Literal(str(step3name))))
                    g.add((new_individual_uri3, ns.has_next, new_individual_uri4))
                    new_individual_uriact3=URIRef("http://kevin.abouahmed/IncidentResponseOntologyPlaybook#"+reactid3)
                    g.add((new_individual_uri3, ns.is_action, new_individual_uriact3))

                    g.add((new_individual_uri4, RDF.type, new_individual_type4))
                    g.add((new_individual_uri4, RDF.type, ns.Playbook_Step))
                    g.add((new_individual_uri4, RDFS.label, Literal(str(step4name))))
                    new_individual_uriact4=URIRef("http://kevin.abouahmed/IncidentResponseOntologyPlaybook#"+reactid4)
                    g.add((new_individual_uri4, ns.is_action, new_individual_uriact4))
                    playbook4='<owl:NamedIndividual rdf:about="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+step3name+'">\n<rdf:type rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#Playbook_Step"/>\n<IncidentResponseOntologyPlaybook:has_next rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+step4name+'"/>\n<IncidentResponseOntologyPlaybook:is_action rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+reactid3+'"/>\n<rdfs:label>'+step3name+'</rdfs:label></owl:NamedIndividual>'
                    playbook4_2='<owl:NamedIndividual rdf:about="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+step4name+'">\n<rdf:type rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#Playbook_Step"/>\n<IncidentResponseOntologyPlaybook:is_action rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+reactid4+'"/>\n<rdfs:label>'+step4name+'</rdfs:label>\n</owl:NamedIndividual>'
          if i==4:
            if phase4!=max_impact_item[i]['phase']:
              print(action_Step4)
              action_Step5=max_impact_item[i]['action']
              phase5=max_impact_item[i]['phase']
              category5=max_impact_item[i]['category']
              reactid5=searchid(action_Step5)
              step5name="Step5_"+cve
              new_individual_uri5 = URIRef("http://kevin.abouahmed/IncidentResponseOntologyPlaybook#"+step5name)
              new_individual_type5 = URIRef("http://www.w3.org/2002/07/owl#NamedIndividual")
              g.add((new_individual_uri4, RDF.type, new_individual_type4))
              g.add((new_individual_uri4, RDF.type, ns.Playbook_Step))
              g.add((new_individual_uri4, RDFS.label, Literal(str(step4name))))
              g.add((new_individual_uri4, ns.has_next, new_individual_uri5))
              new_individual_uriact4=URIRef("http://kevin.abouahmed/IncidentResponseOntologyPlaybook#"+reactid4)
              g.add((new_individual_uri4, ns.is_action, new_individual_uriact4))
              playbook5='<owl:NamedIndividual rdf:about="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+step4name+'">\n<rdf:type rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#Playbook_Step"/>\n<IncidentResponseOntologyPlaybook:has_next rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+step5name+'"/>\n<IncidentResponseOntologyPlaybook:is_action rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+reactid4+'"/>\n<rdfs:label>'+step4name+'</rdfs:label></owl:NamedIndividual>'
            else:
              if category4!=max_impact_item[i]['category']:
                action_Step5=max_impact_item[i]['action']
                phase5=max_impact_item[i]['phase']
                reactid5=searchid(action_Step5)
                category5=max_impact_item[i]['category']
                step5name="Step5_"+cve
                new_individual_uri5 = URIRef("http://kevin.abouahmed/IncidentResponseOntologyPlaybook#"+step5name)
                new_individual_type5 = URIRef("http://www.w3.org/2002/07/owl#NamedIndividual")
                g.add((new_individual_uri4, RDF.type, new_individual_type4))
                g.add((new_individual_uri4, RDF.type, ns.Playbook_Step))
                g.add((new_individual_uri4, RDFS.label, Literal(str(step4name))))
                g.add((new_individual_uri4, ns.parallel, new_individual_uri5))
                new_individual_uriact4=URIRef("http://kevin.abouahmed/IncidentResponseOntologyPlaybook#"+reactid4)
                g.add((new_individual_uri4, ns.is_action, new_individual_uriact4))

                g.add((new_individual_uri5, RDF.type, new_individual_type5))
                g.add((new_individual_uri5, RDF.type, ns.Playbook_Step))
                g.add((new_individual_uri5, RDFS.label, Literal(str(step5name))))
                new_individual_uriact5=URIRef("http://kevin.abouahmed/IncidentResponseOntologyPlaybook#"+reactid5)
                g.add((new_individual_uri5, ns.is_action, new_individual_uriact5))
                playbook5='<owl:NamedIndividual rdf:about="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+step4name+'">\n<rdf:type rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#Playbook_Step"/>\n<IncidentResponseOntologyPlaybook:parallel rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+step5name+'"/>\n<IncidentResponseOntologyPlaybook:is_action rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+reactid4+'"/>\n<rdfs:label>'+step4name+'</rdfs:label></owl:NamedIndividual>'
                playbook5_2='<owl:NamedIndividual rdf:about="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+step5name+'">\n<rdf:type rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#Playbook_Step"/>\n<IncidentResponseOntologyPlaybook:is_action rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+reactid5+'"/>\n<rdfs:label>'+step5name+'</rdfs:label>\n</owl:NamedIndividual>'
              else:
                if i!=len(max_impact_item)-1:
                  action_Step5=max_impact_item[i]['action']
                  phase5=max_impact_item[i]['phase']
                  category5=max_impact_item[i]['category']
                  reactid5=searchid(action_Step5)
                  step5name="Step5_"+cve
                  new_individual_uri5 = URIRef("http://kevin.abouahmed/IncidentResponseOntologyPlaybook#"+step5name)
                  new_individual_type5 = URIRef("http://www.w3.org/2002/07/owl#NamedIndividual")
                  g.add((new_individual_uri4, RDF.type, new_individual_type4))
                  g.add((new_individual_uri4, RDF.type, ns.Playbook_Step))
                  g.add((new_individual_uri4, RDFS.label, Literal(str(step4name))))
                  g.add((new_individual_uri4, ns.has_next, new_individual_uri5))
                  new_individual_uriact4=URIRef("http://kevin.abouahmed/IncidentResponseOntologyPlaybook#"+reactid4)
                  g.add((new_individual_uri4, ns.is_action, new_individual_uriact4))
                  playbook5='<owl:NamedIndividual rdf:about="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+step4name+'">\n<rdf:type rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#Playbook_Step"/>\n<IncidentResponseOntologyPlaybook:has_next rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+step5name+'"/>\n<IncidentResponseOntologyPlaybook:is_action rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+reactid4+'"/>\n<rdfs:label>'+step4name+'</rdfs:label></owl:NamedIndividual>'
                else:
                    action_Step5=max_impact_item[i]['action']
                    phase5=max_impact_item[i]['phase']
                    category5=max_impact_item[i]['category']
                    reactid5=searchid(action_Step5)
                    step5name="Step5_"+cve
                    new_individual_uri5 = URIRef("http://kevin.abouahmed/IncidentResponseOntologyPlaybook#"+step5name)
                    new_individual_type5 = URIRef("http://www.w3.org/2002/07/owl#NamedIndividual")
                    g.add((new_individual_uri4, RDF.type, new_individual_type4))
                    g.add((new_individual_uri4, RDF.type, ns.Playbook_Step))
                    g.add((new_individual_uri4, RDFS.label, Literal(str(step4name))))
                    g.add((new_individual_uri4, ns.has_next, new_individual_uri5))
                    new_individual_uriact4=URIRef("http://kevin.abouahmed/IncidentResponseOntologyPlaybook#"+reactid4)
                    g.add((new_individual_uri4, ns.is_action, new_individual_uriact4))

                    g.add((new_individual_uri5, RDF.type, new_individual_type5))
                    g.add((new_individual_uri5, RDF.type, ns.Playbook_Step))
                    g.add((new_individual_uri5, RDFS.label, Literal(str(step5name))))
                    new_individual_uriact5=URIRef("http://kevin.abouahmed/IncidentResponseOntologyPlaybook#"+reactid5)
                    g.add((new_individual_uri5, ns.is_action, new_individual_uriact5))
                    playbook5='<owl:NamedIndividual rdf:about="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+step4name+'">\n<rdf:type rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#Playbook_Step"/>\n<IncidentResponseOntologyPlaybook:has_next rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+step5name+'"/>\n<IncidentResponseOntologyPlaybook:is_action rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+reactid4+'"/>\n<rdfs:label>'+step4name+'</rdfs:label></owl:NamedIndividual>'
                    playbook5_2='<owl:NamedIndividual rdf:about="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+step5name+'">\n<rdf:type rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#Playbook_Step"/>\n<IncidentResponseOntologyPlaybook:is_action rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+reactid5+'"/>\n<rdfs:label>'+step5name+'</rdfs:label>\n</owl:NamedIndividual>'
          if i==5:
            if phase5!=max_impact_item[i]['phase']:
              action_Step6=max_impact_item[i]['action']
              phase6=max_impact_item[i]['phase']
              category6=max_impact_item[i]['category']
              reactid6=searchid(action_Step6)
              step6name="Step6_"+cve
              new_individual_uri6 = URIRef("http://kevin.abouahmed/IncidentResponseOntologyPlaybook#"+step6name)
              new_individual_type6 = URIRef("http://www.w3.org/2002/07/owl#NamedIndividual")
              g.add((new_individual_uri5, RDF.type, new_individual_type5))
              g.add((new_individual_uri5, RDF.type, ns.Playbook_Step))
              g.add((new_individual_uri5, RDFS.label, Literal(str(step5name))))
              g.add((new_individual_uri5, ns.has_next, new_individual_uri6))
              new_individual_uriact5=URIRef("http://kevin.abouahmed/IncidentResponseOntologyPlaybook#"+reactid5)
              g.add((new_individual_uri5, ns.is_action, new_individual_uriact5))
              playbook6='<owl:NamedIndividual rdf:about="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+step5name+'">\n<rdf:type rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#Playbook_Step"/>\n<IncidentResponseOntologyPlaybook:has_next rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+step6name+'"/>\n<IncidentResponseOntologyPlaybook:is_action rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+reactid5+'"/>\n<rdfs:label>'+step5name+'</rdfs:label></owl:NamedIndividual>'
            else:
              if category5!=max_impact_item[i]['category']:
                action_Step6=max_impact_item[i]['action']
                phase6=max_impact_item[i]['phase']
                reactid6=searchid(action_Step6)
                step6name="Step6_"+cve
                new_individual_uri6 = URIRef("http://kevin.abouahmed/IncidentResponseOntologyPlaybook#"+step6name)
                new_individual_type6 = URIRef("http://www.w3.org/2002/07/owl#NamedIndividual")
                g.add((new_individual_uri5, RDF.type, new_individual_type5))
                g.add((new_individual_uri5, RDF.type, ns.Playbook_Step))
                g.add((new_individual_uri5, RDFS.label, Literal(str(step5name))))
                g.add((new_individual_uri5, ns.parallel, new_individual_uri6))
                new_individual_uriact5=URIRef("http://kevin.abouahmed/IncidentResponseOntologyPlaybook#"+reactid5)
                g.add((new_individual_uri5, ns.is_action, new_individual_uriact5))

                g.add((new_individual_uri6, RDF.type, new_individual_type6))
                g.add((new_individual_uri6, RDF.type, ns.Playbook_Step))
                g.add((new_individual_uri6, RDFS.label, Literal(str(step6name))))
                new_individual_uriact6=URIRef("http://kevin.abouahmed/IncidentResponseOntologyPlaybook#"+reactid6)
                g.add((new_individual_uri6, ns.is_action, new_individual_uriact6))
                playbook6='<owl:NamedIndividual rdf:about="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+step5name+'">\n<rdf:type rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#Playbook_Step"/>\n<IncidentResponseOntologyPlaybook:parallel rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+step6name+'"/>\n<IncidentResponseOntologyPlaybook:is_action rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+reactid5+'"/>\n<rdfs:label>'+step5name+'</rdfs:label></owl:NamedIndividual>'
                playbook6_2='<owl:NamedIndividual rdf:about="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+step6name+'">\n<rdf:type rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#Playbook_Step"/>\n<IncidentResponseOntologyPlaybook:is_action rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+reactid6+'"/>\n<rdfs:label>'+step6name+'</rdfs:label>\n</owl:NamedIndividual>'
              else:
                if i!=len(max_impact_item)-1:
                  action_Step6=max_impact_item[i]['action']
                  phase6=max_impact_item[i]['phase']
                  reactid6=searchid(action_Step6)
                  step6name="Step6_"+cve
                  new_individual_uri6 = URIRef("http://kevin.abouahmed/IncidentResponseOntologyPlaybook#"+step6name)
                  new_individual_type6 = URIRef("http://www.w3.org/2002/07/owl#NamedIndividual")
                  g.add((new_individual_uri5, RDF.type, new_individual_type5))
                  g.add((new_individual_uri5, RDF.type, ns.Playbook_Step))
                  g.add((new_individual_uri5, RDFS.label, Literal(str(step5name))))
                  g.add((new_individual_uri5, ns.has_next, new_individual_uri6))
                  new_individual_uriact5=URIRef("http://kevin.abouahmed/IncidentResponseOntologyPlaybook#"+reactid5)
                  g.add((new_individual_uri5, ns.is_action, new_individual_uriact5))
                  playbook6='<owl:NamedIndividual rdf:about="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+step5name+'">\n<rdf:type rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#Playbook_Step"/>\n<IncidentResponseOntologyPlaybook:has_next rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+step6name+'"/>\n<IncidentResponseOntologyPlaybook:is_action rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+reactid5+'"/>\n<rdfs:label>'+step5name+'</rdfs:label></owl:NamedIndividual>'
                  #playbook6_2='<owl:NamedIndividual rdf:about="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+step6name+'">\n<rdf:type rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#Playbook_Step"/>\n<IncidentResponseOntologyPlaybook:is_action rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+reactid6+'"/>\n<rdfs:label>'+step6name+'</rdfs:label>\n</owl:NamedIndividual>'
                else:
                  action_Step6=max_impact_item[i]['action']
                  phase6=max_impact_item[i]['phase']
                  reactid6=searchid(action_Step6)
                  step6name="Step6_"+cve
                  new_individual_uri6 = URIRef("http://kevin.abouahmed/IncidentResponseOntologyPlaybook#"+step6name)
                  new_individual_type6 = URIRef("http://www.w3.org/2002/07/owl#NamedIndividual")
                  g.add((new_individual_uri5, RDF.type, new_individual_type5))
                  g.add((new_individual_uri5, RDF.type, ns.Playbook_Step))
                  g.add((new_individual_uri5, RDFS.label, Literal(str(step5name))))
                  g.add((new_individual_uri5, ns.has_next, new_individual_uri6))
                  new_individual_uriact5=URIRef("http://kevin.abouahmed/IncidentResponseOntologyPlaybook#"+reactid5)
                  g.add((new_individual_uri5, ns.is_action, new_individual_uriact5))

                  g.add((new_individual_uri6, RDF.type, new_individual_type6))
                  g.add((new_individual_uri6, RDF.type, ns.Playbook_Step))
                  g.add((new_individual_uri6, RDFS.label, Literal(str(step6name))))
                  new_individual_uriact6=URIRef("http://kevin.abouahmed/IncidentResponseOntologyPlaybook#"+reactid6)
                  g.add((new_individual_uri6, ns.is_action, new_individual_uriact6))
                  playbook6='<owl:NamedIndividual rdf:about="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+step5name+'">\n<rdf:type rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#Playbook_Step"/>\n<IncidentResponseOntologyPlaybook:has_next rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+step6name+'"/>\n<IncidentResponseOntologyPlaybook:is_action rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+reactid5+'"/>\n<rdfs:label>'+step5name+'</rdfs:label></owl:NamedIndividual>'
                  playbook6_2='<owl:NamedIndividual rdf:about="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+step6name+'">\n<rdf:type rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#Playbook_Step"/>\n<IncidentResponseOntologyPlaybook:is_action rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+reactid6+'"/>\n<rdfs:label>'+step6name+'</rdfs:label>\n</owl:NamedIndividual>'
          if i==6:
            if phase6!=max_impact_item[i]['phase']:
              action_Step7=max_impact_item[i]['action']
              phase7=max_impact_item[i]['phase']
              reactid7=searchid(action_Step7)
              step7name="Step7_"+cve
              new_individual_uri7 = URIRef("http://kevin.abouahmed/IncidentResponseOntologyPlaybook#"+step7name)
              new_individual_type7 = URIRef("http://www.w3.org/2002/07/owl#NamedIndividual")
              g.add((new_individual_uri6, RDF.type, new_individual_type6))
              g.add((new_individual_uri6, RDF.type, ns.Playbook_Step))
              g.add((new_individual_uri6, RDFS.label, Literal(str(step6name))))
              g.add((new_individual_uri6, ns.has_next, new_individual_uri7))
              new_individual_uriact6=URIRef("http://kevin.abouahmed/IncidentResponseOntologyPlaybook#"+reactid6)
              g.add((new_individual_uri6, ns.is_action, new_individual_uriact6))
              playbook7='<owl:NamedIndividual rdf:about="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+step6name+'">\n<rdf:type rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#Playbook_Step"/>\n<IncidentResponseOntologyPlaybook:has_next rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+step7name+'"/>\n<IncidentResponseOntologyPlaybook:is_action rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+reactid6+'"/>\n<rdfs:label>'+step6name+'</rdfs:label></owl:NamedIndividual>'
            else:
              if i==6 and phase6==max_impact_item[i]['phase']:
                if category6!=max_impact_item[i]['category']:
                  action_Step7=max_impact_item[i]['action']
                  phase7=max_impact_item[i]['phase']
                  reactid7=searchid(action_Step7)
                  step7name="Step7_"+cve
                  new_individual_uri7 = URIRef("http://kevin.abouahmed/IncidentResponseOntologyPlaybook#"+step7name)
                  new_individual_type7 = URIRef("http://www.w3.org/2002/07/owl#NamedIndividual")
                  g.add((new_individual_uri6, RDF.type, new_individual_type6))
                  g.add((new_individual_uri6, RDF.type, ns.Playbook_Step))
                  g.add((new_individual_uri6, RDFS.label, Literal(str(step6name))))
                  g.add((new_individual_uri6, ns.parallel, new_individual_uri7))
                  new_individual_uriact6=URIRef("http://kevin.abouahmed/IncidentResponseOntologyPlaybook#"+reactid6)
                  g.add((new_individual_uri6, ns.is_action, new_individual_uriact6))

                  g.add((new_individual_uri7, RDF.type, new_individual_type7))
                  g.add((new_individual_uri7, RDF.type, ns.Playbook_Step))
                  g.add((new_individual_uri7, RDFS.label, Literal(str(step7name))))
                  new_individual_uriact7=URIRef("http://kevin.abouahmed/IncidentResponseOntologyPlaybook#"+reactid7)
                  g.add((new_individual_uri7, ns.is_action, new_individual_uriact7))
                  playbook7='<owl:NamedIndividual rdf:about="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+step6name+'">\n<rdf:type rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#Playbook_Step"/>\n<IncidentResponseOntologyPlaybook:parallel rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+step7name+'"/>\n<IncidentResponseOntologyPlaybook:is_action rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+reactid6+'"/>\n<rdfs:label>'+step6name+'</rdfs:label></owl:NamedIndividual>'
                  playbook7_2='<owl:NamedIndividual rdf:about="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+step7name+'">\n<rdf:type rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#Playbook_Step"/>\n<IncidentResponseOntologyPlaybook:is_action rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+reactid7+'"/>\n<rdfs:label>'+step7name+'</rdfs:label>\n</owl:NamedIndividual>'
                else:
                  if i!=len(max_impact_item)-1:
                    action_Step7=max_impact_item[i]['action']
                    phase7=max_impact_item[i]['phase']
                    reactid7=searchid(action_Step7)
                    step7name="Step7_"+cve
                    new_individual_uri7 = URIRef("http://kevin.abouahmed/IncidentResponseOntologyPlaybook#"+step7name)
                    new_individual_type7 = URIRef("http://www.w3.org/2002/07/owl#NamedIndividual")
                    g.add((new_individual_uri6, RDF.type, new_individual_type6))
                    g.add((new_individual_uri6, RDF.type, ns.Playbook_Step))
                    g.add((new_individual_uri6, RDFS.label, Literal(str(step6name))))
                    g.add((new_individual_uri6, ns.has_next, new_individual_uri7))
                    new_individual_uriact6=URIRef("http://kevin.abouahmed/IncidentResponseOntologyPlaybook#"+reactid6)
                    g.add((new_individual_uri6, ns.is_action, new_individual_uriact6))
                    playbook7='<owl:NamedIndividual rdf:about="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+step6name+'">\n<rdf:type rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#Playbook_Step"/>\n<IncidentResponseOntologyPlaybook:has_next rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+step7name+'"/>\n<IncidentResponseOntologyPlaybook:is_action rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+reactid6+'"/>\n<rdfs:label>'+step6name+'</rdfs:label></owl:NamedIndividual>'
                  else:
                    action_Step7=max_impact_item[i]['action']
                    phase7=max_impact_item[i]['phase']
                    reactid7=searchid(action_Step7)
                    step7name="Step7_"+cve
                    new_individual_uri7 = URIRef("http://kevin.abouahmed/IncidentResponseOntologyPlaybook#"+step7name)
                    new_individual_type7 = URIRef("http://www.w3.org/2002/07/owl#NamedIndividual")
                    g.add((new_individual_uri6, RDF.type, new_individual_type6))
                    g.add((new_individual_uri6, RDF.type, ns.Playbook_Step))
                    g.add((new_individual_uri6, RDFS.label, Literal(str(step6name))))
                    g.add((new_individual_uri6, ns.has_next, new_individual_uri7))
                    new_individual_uriact6=URIRef("http://kevin.abouahmed/IncidentResponseOntologyPlaybook#"+reactid6)
                    g.add((new_individual_uri6, ns.is_action, new_individual_uriact6))

                    g.add((new_individual_uri7, RDF.type, new_individual_type7))
                    g.add((new_individual_uri7, RDF.type, ns.Playbook_Step))
                    g.add((new_individual_uri7, RDFS.label, Literal(str(step7name))))
                    new_individual_uriact7=URIRef("http://kevin.abouahmed/IncidentResponseOntologyPlaybook#"+reactid7)
                    g.add((new_individual_uri7, ns.is_action, new_individual_uriact7))
                    playbook7='<owl:NamedIndividual rdf:about="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+step6name+'">\n<rdf:type rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#Playbook_Step"/>\n<IncidentResponseOntologyPlaybook:has_next rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+step7name+'"/>\n<IncidentResponseOntologyPlaybook:is_action rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+reactid6+'"/>\n<rdfs:label>'+step6name+'</rdfs:label></owl:NamedIndividual>'
                    playbook7_2='<owl:NamedIndividual rdf:about="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+step7name+'">\n<rdf:type rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#Playbook_Step"/>\n<IncidentResponseOntologyPlaybook:is_action rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+reactid7+'"/>\n<rdfs:label>'+step7name+'</rdfs:label>\n</owl:NamedIndividual>'
                  # print(len(max_impact_item))

      g.serialize(destination=path, format="ttl")
    else:
      print("length 0")
      # Load your TTL file into an RDF graph
      filename = "/var/www/html/ADG/play.owl"
      path = "" + filename
      g = Graph()
      g.parse(path, format="ttl")

      # Define your custom tag namespace
      ns = Namespace("http://kevin.abouahmed/IncidentResponseOntologyPlaybook#")
      playbookname="Playbook_"+cve
      action_Step1="list host vulnerabilities"
      phase1=2
      category1=0
      reactid1="RA2002"
      step1name="Step1_"+cve
      new_individual_uriplay = URIRef("http://kevin.abouahmed/IncidentResponseOntologyPlaybook#"+playbookname)
      new_individual_typeplay = URIRef("http://www.w3.org/2002/07/owl#NamedIndividual")
      g.add((new_individual_uriplay, RDF.type, new_individual_typeplay))
      g.add((new_individual_uriplay, RDF.type, ns.Playbook))
      new_individual_uri = URIRef("http://kevin.abouahmed/IncidentResponseOntologyPlaybook#"+step1name)
      new_individual_type = URIRef("http://www.w3.org/2002/07/owl#NamedIndividual")
      g.add((new_individual_uriplay, RDFS.label, Literal("Playbook : Response to "+cve)))
      g.add((new_individual_uriplay, ns.has_description, Literal("This playbook is intended to answer the vulnerability identified by the ID "+cve)))
      g.add((new_individual_uriplay, ns.has_coa, new_individual_uri))
      playbook1='<owl:NamedIndividual rdf:about="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+playbookname+'">\n<rdf:type rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#Playbook"/>\n<IncidentResponseOntologyPlaybook:has_coa rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+step1name+'"/>\n<IncidentResponseOntologyPlaybook:has_description>This playbook is intended to answer the vulnerability identified by the ID'+cve+'</IncidentResponseOntologyPlaybook:has_description>\n<rdfs:label>Playbook : Response to '+cve+'</rdfs:label>\n</owl:NamedIndividual>'
      action_Step2="patch vulnerability"
      phase2=3
      category2=0
      reactid2="RA3001"
      step2name="Step2_"+cve
      new_individual_uri2 = URIRef("http://kevin.abouahmed/IncidentResponseOntologyPlaybook#"+step2name)
      new_individual_type2 = URIRef("http://www.w3.org/2002/07/owl#NamedIndividual")
      g.add((new_individual_uri, RDF.type, new_individual_type))
      g.add((new_individual_uri, RDF.type, ns.Playbook_Step))
      g.add((new_individual_uri, RDFS.label, Literal(str(step1name))))
      g.add((new_individual_uri, ns.has_next, new_individual_uri2))
      new_individual_uriact=URIRef("http://kevin.abouahmed/IncidentResponseOntologyPlaybook#"+reactid1)
      g.add((new_individual_uri, ns.is_action, new_individual_uriact))
      playbook2='<owl:NamedIndividual rdf:about="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+step1name+'">\n<rdf:type rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#Playbook_Step"/>\n<IncidentResponseOntologyPlaybook:has_next rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+step2name+'"/>\n<IncidentResponseOntologyPlaybook:is_action rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+reactid1+'"/>\n<rdfs:label>'+step1name+'</rdfs:label></owl:NamedIndividual>'
      action_Step3="develop incident report"
      phase3=6
      category3=0
      reactid3="RA6001"
      step3name="Step3_"+cve
      new_individual_uri3 = URIRef("http://kevin.abouahmed/IncidentResponseOntologyPlaybook#"+step3name)
      new_individual_type3 = URIRef("http://www.w3.org/2002/07/owl#NamedIndividual")
      g.add((new_individual_uri2, RDF.type, new_individual_type2))
      g.add((new_individual_uri2, RDF.type, ns.Playbook_Step))
      g.add((new_individual_uri2, RDFS.label, Literal(str(step2name))))
      g.add((new_individual_uri2, ns.has_next, new_individual_uri3))
      new_individual_uriact2=URIRef("http://kevin.abouahmed/IncidentResponseOntologyPlaybook#"+reactid2)
      g.add((new_individual_uri2, ns.is_action, new_individual_uriact2))
      playbook3='<owl:NamedIndividual rdf:about="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+step2name+'">\n<rdf:type rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#Playbook_Step"/>\n<IncidentResponseOntologyPlaybook:has_next rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+step3name+'"/>\n<IncidentResponseOntologyPlaybook:is_action rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+reactid2+'"/>\n<rdfs:label>'+step2name+'</rdfs:label></owl:NamedIndividual>'
      action_Step4="conduct lessons learned exercise"
      phase4=6
      category4=0
      reactid4="RA6002"
      step4name="Step4_"+cve
      new_individual_uri4 = URIRef("http://kevin.abouahmed/IncidentResponseOntologyPlaybook#"+step4name)
      new_individual_type4 = URIRef("http://www.w3.org/2002/07/owl#NamedIndividual")
      g.add((new_individual_uri3, RDF.type, new_individual_type3))
      g.add((new_individual_uri3, RDF.type, ns.Playbook_Step))
      g.add((new_individual_uri3, RDFS.label, Literal(str(step3name))))
      g.add((new_individual_uri3, ns.has_next, new_individual_uri4))
      new_individual_uriact3=URIRef("http://kevin.abouahmed/IncidentResponseOntologyPlaybook#"+reactid3)
      g.add((new_individual_uri3, ns.is_action, new_individual_uriact3))

      g.add((new_individual_uri4, RDF.type, new_individual_type4))
      g.add((new_individual_uri4, RDF.type, ns.Playbook_Step))
      g.add((new_individual_uri4, RDFS.label, Literal(str(step4name))))
      new_individual_uriact4=URIRef("http://kevin.abouahmed/IncidentResponseOntologyPlaybook#"+reactid4)
      g.add((new_individual_uri4, ns.is_action, new_individual_uriact4))
      playbook4='<owl:NamedIndividual rdf:about="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+step3name+'">\n<rdf:type rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#Playbook_Step"/>\n<IncidentResponseOntologyPlaybook:has_next rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+step4name+'"/>\n<IncidentResponseOntologyPlaybook:is_action rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+reactid3+'"/>\n<rdfs:label>'+step3name+'</rdfs:label></owl:NamedIndividual>'
      playbook4_2='<owl:NamedIndividual rdf:about="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+step4name+'">\n<rdf:type rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#Playbook_Step"/>\n<IncidentResponseOntologyPlaybook:is_action rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+reactid4+'"/>\n<rdfs:label>'+step4name+'</rdfs:label>\n</owl:NamedIndividual>'
      g.serialize(destination=path, format="ttl")
  else:
    print("length 0")
    # Load your TTL file into an RDF graph
    filename = "/var/www/html/ADG/play.owl"
    path = "" + filename
    g = Graph()
    g.parse(path, format="ttl")

    # Define your custom tag namespace
    ns = Namespace("http://kevin.abouahmed/IncidentResponseOntologyPlaybook#")
    playbookname="Playbook_"+cve
    action_Step1="list host vulnerabilities"
    phase1=2
    category1=0
    reactid1="RA2002"
    step1name="Step1_"+cve
    new_individual_uriplay = URIRef("http://kevin.abouahmed/IncidentResponseOntologyPlaybook#"+playbookname)
    new_individual_typeplay = URIRef("http://www.w3.org/2002/07/owl#NamedIndividual")
    g.add((new_individual_uriplay, RDF.type, new_individual_typeplay))
    g.add((new_individual_uriplay, RDF.type, ns.Playbook))
    new_individual_uri = URIRef("http://kevin.abouahmed/IncidentResponseOntologyPlaybook#"+step1name)
    new_individual_type = URIRef("http://www.w3.org/2002/07/owl#NamedIndividual")
    g.add((new_individual_uriplay, RDFS.label, Literal("Playbook : Response to "+cve)))
    g.add((new_individual_uriplay, ns.has_description, Literal("This playbook is intended to answer the vulnerability identified by the ID "+cve)))
    g.add((new_individual_uriplay, ns.has_coa, new_individual_uri))
    playbook1='<owl:NamedIndividual rdf:about="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+playbookname+'">\n<rdf:type rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#Playbook"/>\n<IncidentResponseOntologyPlaybook:has_coa rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+step1name+'"/>\n<IncidentResponseOntologyPlaybook:has_description>This playbook is intended to answer the vulnerability identified by the ID'+cve+'</IncidentResponseOntologyPlaybook:has_description>\n<rdfs:label>Playbook : Response to '+cve+'</rdfs:label>\n</owl:NamedIndividual>'
    action_Step2="patch vulnerability"
    phase2=3
    category2=0
    reactid2="RA3001"
    step2name="Step2_"+cve
    new_individual_uri2 = URIRef("http://kevin.abouahmed/IncidentResponseOntologyPlaybook#"+step2name)
    new_individual_type2 = URIRef("http://www.w3.org/2002/07/owl#NamedIndividual")
    g.add((new_individual_uri, RDF.type, new_individual_type))
    g.add((new_individual_uri, RDF.type, ns.Playbook_Step))
    g.add((new_individual_uri, RDFS.label, Literal(str(step1name))))
    g.add((new_individual_uri, ns.has_next, new_individual_uri2))
    new_individual_uriact=URIRef("http://kevin.abouahmed/IncidentResponseOntologyPlaybook#"+reactid1)
    g.add((new_individual_uri, ns.is_action, new_individual_uriact))
    playbook2='<owl:NamedIndividual rdf:about="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+step1name+'">\n<rdf:type rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#Playbook_Step"/>\n<IncidentResponseOntologyPlaybook:has_next rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+step2name+'"/>\n<IncidentResponseOntologyPlaybook:is_action rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+reactid1+'"/>\n<rdfs:label>'+step1name+'</rdfs:label></owl:NamedIndividual>'
    action_Step3="develop incident report"
    phase3=6
    category3=0
    reactid3="RA6001"
    step3name="Step3_"+cve
    new_individual_uri3 = URIRef("http://kevin.abouahmed/IncidentResponseOntologyPlaybook#"+step3name)
    new_individual_type3 = URIRef("http://www.w3.org/2002/07/owl#NamedIndividual")
    g.add((new_individual_uri2, RDF.type, new_individual_type2))
    g.add((new_individual_uri2, RDF.type, ns.Playbook_Step))
    g.add((new_individual_uri2, RDFS.label, Literal(str(step2name))))
    g.add((new_individual_uri2, ns.has_next, new_individual_uri3))
    new_individual_uriact2=URIRef("http://kevin.abouahmed/IncidentResponseOntologyPlaybook#"+reactid2)
    g.add((new_individual_uri2, ns.is_action, new_individual_uriact2))
    playbook3='<owl:NamedIndividual rdf:about="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+step2name+'">\n<rdf:type rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#Playbook_Step"/>\n<IncidentResponseOntologyPlaybook:has_next rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+step3name+'"/>\n<IncidentResponseOntologyPlaybook:is_action rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+reactid2+'"/>\n<rdfs:label>'+step2name+'</rdfs:label></owl:NamedIndividual>'
    action_Step4="conduct lessons learned exercise"
    phase4=6
    category4=0
    reactid4="RA6002"
    step4name="Step4_"+cve
    new_individual_uri4 = URIRef("http://kevin.abouahmed/IncidentResponseOntologyPlaybook#"+step4name)
    new_individual_type4 = URIRef("http://www.w3.org/2002/07/owl#NamedIndividual")
    g.add((new_individual_uri3, RDF.type, new_individual_type3))
    g.add((new_individual_uri3, RDF.type, ns.Playbook_Step))
    g.add((new_individual_uri3, RDFS.label, Literal(str(step3name))))
    g.add((new_individual_uri3, ns.has_next, new_individual_uri4))
    new_individual_uriact3=URIRef("http://kevin.abouahmed/IncidentResponseOntologyPlaybook#"+reactid3)
    g.add((new_individual_uri3, ns.is_action, new_individual_uriact3))

    g.add((new_individual_uri4, RDF.type, new_individual_type4))
    g.add((new_individual_uri4, RDF.type, ns.Playbook_Step))
    g.add((new_individual_uri4, RDFS.label, Literal(str(step4name))))
    new_individual_uriact4=URIRef("http://kevin.abouahmed/IncidentResponseOntologyPlaybook#"+reactid4)
    g.add((new_individual_uri4, ns.is_action, new_individual_uriact4))
    playbook4='<owl:NamedIndividual rdf:about="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+step3name+'">\n<rdf:type rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#Playbook_Step"/>\n<IncidentResponseOntologyPlaybook:has_next rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+step4name+'"/>\n<IncidentResponseOntologyPlaybook:is_action rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+reactid3+'"/>\n<rdfs:label>'+step3name+'</rdfs:label></owl:NamedIndividual>'
    playbook4_2='<owl:NamedIndividual rdf:about="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+step4name+'">\n<rdf:type rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#Playbook_Step"/>\n<IncidentResponseOntologyPlaybook:is_action rdf:resource="http://kevin.abouahmed/IncidentResponseOntologyPlaybook#'+reactid4+'"/>\n<rdfs:label>'+step4name+'</rdfs:label>\n</owl:NamedIndividual>'
    g.serialize(destination=path, format="ttl")
def readtsv(cve,filename):
   # Simple Way to Read TSV Files in Python using csv

  listaction=[]
  listphase=[]
  listimpact=[]
  listcomplexity=[]
  listloss=[]
  listrequirement=[]
  listcategory=[]
  # Opening JSON file
  f = open('/var/www/html/ADG/RE&CT_Enterprise_Matrix.json')

  # returns JSON object as
  # a dictionary
  data = json.load(f)

  # Iterating through the json
  # list
  preparationgeneral, preparationprocess, preparationnetwork, preparationemail, preparationfile, preparationidentity, preparationconfiguration=[], [], [], [], [], [], []
  identificationgeneral, identificationprocess, identificationnetwork, identificationemail, identificationfile, identificationidentity, identificationconfiguration=[], [], [], [], [], [], []
  containmentgeneral, containmentprocess, containmentnetwork, containmentemail, containmentfile, containmentidentity, containmentconfiguration=[], [], [], [], [], [], []
  eradicationgeneral, eradicationprocess, eradicationnetwork, eradicationemail, eradicationfile, eradicationidentity, eradicationconfiguration=[], [], [], [], [], [], []
  recoverygeneral, recoveryprocess, recoverynetwork, recoveryemail, recoveryfile, recoveryidentity, recoveryconfiguration=[], [], [], [], [], [], []
  lessonsgeneral=[]
  for i in data['techniques']:
      if i['tactic']=='preparation' and i['color']=='#ffd300':
        preparationgeneral.append(i['techniqueID'])
      if i['tactic']=='preparation' and i['color']=='#075190':
        preparationprocess.append(i['techniqueID'])
      if i['tactic']=='preparation' and i['color']=='#abc530':
        preparationnetwork.append(i['techniqueID'])
      if i['tactic']=='preparation' and i['color']=='#01c26d':
        preparationemail.append(i['techniqueID'])
      if i['tactic']=='preparation' and i['color']=='#007B84':
        preparationfile.append(i['techniqueID'])
      if i['tactic']=='preparation' and i['color']=='#482569':
        preparationidentity.append(i['techniqueID'])
      if i['tactic']=='preparation' and i['color']=='#86308c':
        preparationconfiguration.append(i['techniqueID'])
      if i['tactic']=='identification' and i['color']=='#ffd300':
        identificationgeneral.append(i['techniqueID'])
      if i['tactic']=='identification' and i['color']=='#075190':
        identificationprocess.append(i['techniqueID'])
      if i['tactic']=='identification' and i['color']=='#abc530':
        identificationnetwork.append(i['techniqueID'])
      if i['tactic']=='identification' and i['color']=='#01c26d':
        identificationemail.append(i['techniqueID'])
      if i['tactic']=='identification' and i['color']=='#007b84':
        identificationfile.append(i['techniqueID'])
      if i['tactic']=='identification' and i['color']=='#482569':
        identificationidentity.append(i['techniqueID'])
      if i['tactic']=='identification' and i['color']=='#86308c':
        identificationconfiguration.append(i['techniqueID'])
      if i['tactic']=='containment' and i['color']=='#ffd300':
        containmentgeneral.append(i['techniqueID'])
      if i['tactic']=='containment' and i['color']=='#075190':
        containmentprocess.append(i['techniqueID'])
      if i['tactic']=='containment' and i['color']=='#abc530':
        containmentnetwork.append(i['techniqueID'])
      if i['tactic']=='containment' and i['color']=='#01c26d':
        containmentemail.append(i['techniqueID'])
      if i['tactic']=='containment' and i['color']=='#007b84':
        containmentfile.append(i['techniqueID'])
      if i['tactic']=='containment' and i['color']=='#482569':
        containmentidentity.append(i['techniqueID'])
      if i['tactic']=='containment' and i['color']=='#86308c':
        containmentconfiguration.append(i['techniqueID'])
      if i['tactic']=='eradication' and i['color']=='#ffd300':
        eradicationgeneral.append(i['techniqueID'])
      if i['tactic']=='eradication' and i['color']=='#075190':
        eradicationprocess.append(i['techniqueID'])
      if i['tactic']=='eradication' and i['color']=='#abc530':
        eradicationnetwork.append(i['techniqueID'])
      if i['tactic']=='eradication' and i['color']=='#01c26d':
        eradicationemail.append(i['techniqueID'])
      if i['tactic']=='eradication' and i['color']=='#007b84':
        eradicationfile.append(i['techniqueID'])
      if i['tactic']=='eradication' and i['color']=='#482569':
        eradicationidentity.append(i['techniqueID'])
      if i['tactic']=='eradication' and i['color']=='#86308c':
        eradicationconfiguration.append(i['techniqueID'])
      if i['tactic']=='recovery' and i['color']=='#ffd300':
        recoverygeneral.append(i['techniqueID'])
      if i['tactic']=='recovery' and i['color']=='#075190':
        recoveryprocess.append(i['techniqueID'])
      if i['tactic']=='recovery' and i['color']=='#abc530':
        recoverynetwork.append(i['techniqueID'])
      if i['tactic']=='recovery' and i['color']=='#01c26d':
        recoveryemail.append(i['techniqueID'])
      if i['tactic']=='recovery' and i['color']=='#007b84':
        recoveryfile.append(i['techniqueID'])
      if i['tactic']=='recovery' and i['color']=='#482569':
        recoveryidentity.append(i['techniqueID'])
      if i['tactic']=='recovery' and i['color']=='#86308c':
        recoveryconfiguration.append(i['techniqueID'])
      if i['tactic']=='lessons-learned' and i['color']=='#ffd300':
        lessonsgeneral.append(i['techniqueID'])

  # Closing file
  f.close()
  # open .tsv file
  with open(filename) as file:
    
      my_world = World()
      my_world.get_ontology("/var/www/html/ADG/playbook.owl").load() #path to the owl file is given here
      #sync_reasoner(my_world)  #reasoner is started and synchronized here
      graph = my_world.as_rdflib_graph()
      # Passing the TSV file to
      # reader() function
      # with tab delimiter
      # This function will
      # read data from file
      tsv_file = csv.reader(file, delimiter="\t")
      print(tsv_file,cve)
      #CVE='CVE-2016-3085'
      CVE=cve
      # printing data line by line
      for line in tsv_file:
        if line[0]==CVE:
          #print(line[5],line[6])
          if line[5]=='Identification' and line[6]=='Process':
            for e in identificationprocess:
              #print(e)
              if len(searchaction(e))!=0 and searchaction(e)[0] not in listaction:
                listaction.append(searchaction(e)[0])
                listphase.append(2)
                listimpact.append(searchaction(e)[1])
                listcomplexity.append(searchaction(e)[2])
                listloss.append(searchaction(e)[3])
                listrequirement.append(searchaction(e)[4])
                listcategory.append(4)
          if line[5]=='Containment' and line[6]=='Process':
            for e in containmentprocess:
              #print(searchaction(e))
              if len(searchaction(e))!=0 and searchaction(e)[0] not in listaction:
                listaction.append(searchaction(e)[0])
                listphase.append(3)
                listimpact.append(searchaction(e)[1])
                listcomplexity.append(searchaction(e)[2])
                listloss.append(searchaction(e)[3])
                listrequirement.append(searchaction(e)[4])
                listcategory.append(4)
          if line[5]=='Recovery' and line[6]=='Process':
            for e in recoveryprocess:
              #print(searchaction(e))
              if len(searchaction(e))!=0 and searchaction(e)[0] not in listaction:
                listaction.append(searchaction(e)[0])
                listphase.append(5)
                listimpact.append(searchaction(e)[1])
                listcomplexity.append(searchaction(e)[2])
                listloss.append(searchaction(e)[3])
                listrequirement.append(searchaction(e)[4])
                listcategory.append(4)
          if line[5]=='Preparation' and line[6]=='Process':
            for e in preparationprocess:
              #print(searchaction(e))
              if len(searchaction(e))!=0 and searchaction(e)[0] not in listaction:
                listaction.append(searchaction(e)[0])
                listphase.append(1)
                listimpact.append(searchaction(e)[1])
                listcomplexity.append(searchaction(e)[2])
                listloss.append(searchaction(e)[3])
                listrequirement.append(searchaction(e)[4])
                listcategory.append(4)
          if line[5]=='Eradication' and line[6]=='Process':
            for e in eradicationprocess:
              #print(searchaction(e))
              if len(searchaction(e))!=0 and searchaction(e)[0] not in listaction:
                listaction.append(searchaction(e)[0])
                listphase.append(4)
                listimpact.append(searchaction(e)[1])
                listcomplexity.append(searchaction(e)[2])
                listloss.append(searchaction(e)[3])
                listrequirement.append(searchaction(e)[4])
                listcategory.append(4)
          if line[5]=='Lessons Learned' and line[6]=='General':
            for e in lessonsgeneral:
              #print(searchaction(e))
              if len(searchaction(e))!=0 and searchaction(e)[0] not in listaction:
                listaction.append(searchaction(e)[0])
                listphase.append(6)
                listimpact.append(searchaction(e)[1])
                listcomplexity.append(searchaction(e)[2])
                listloss.append(searchaction(e)[3])
                listrequirement.append(searchaction(e)[4])
                listcategory.append(0)
          if line[5]=='Identification' and line[6]=='General':
            for e in identificationgeneral:
              #print(e,identificationgeneral)
              #print(searchaction(e))
              if len(searchaction(e))!=0 and searchaction(e)[0] not in listaction:
                listaction.append(searchaction(e)[0])
                listphase.append(2)
                listimpact.append(searchaction(e)[1])
                listcomplexity.append(searchaction(e)[2])
                listloss.append(searchaction(e)[3])
                listrequirement.append(searchaction(e)[4])
                listcategory.append(0)
          if line[5]=='Containment' and line[6]=='General':
            for e in containmentgeneral:
              print(searchaction(e))
              if len(searchaction(e))!=0 and searchaction(e)[0] not in listaction:
                listaction.append(searchaction(e)[0])
                listphase.append(3)
                listimpact.append(searchaction(e)[1])
                listcomplexity.append(searchaction(e)[2])
                listloss.append(searchaction(e)[3])
                listrequirement.append(searchaction(e)[4])
                listcategory.append(0)
          if line[5]=='Recovery' and line[6]=='General':
            for e in recoverygeneral:
              if len(searchaction(e))!=0 and searchaction(e)[0] not in listaction:
                listaction.append(searchaction(e)[0])
                listphase.append(5)
                listimpact.append(searchaction(e)[1])
                listcomplexity.append(searchaction(e)[2])
                listloss.append(searchaction(e)[3])
                listrequirement.append(searchaction(e)[4])
                listcategory.append(0)
          if line[5]=='Preparation' and line[6]=='General':
            for e in preparationgeneral:
              #print(searchaction(e))
              if len(searchaction(e))!=0 and searchaction(e)[0] not in listaction:
                listaction.append(searchaction(e)[0])
                listphase.append(1)
                listimpact.append(searchaction(e)[1])
                listcomplexity.append(searchaction(e)[2])
                listloss.append(searchaction(e)[3])
                listrequirement.append(searchaction(e)[4])
                listcategory.append(0)
          if line[5]=='Eradication' and line[6]=='General':
            for e in eradicationgeneral:
              #print(searchaction(e))
              if len(searchaction(e))!=0 and searchaction(e)[0] not in listaction:
                listaction.append(searchaction(e)[0])
                listphase.append(4)
                listimpact.append(searchaction(e)[1])
                listcomplexity.append(searchaction(e)[2])
                listloss.append(searchaction(e)[3])
                listrequirement.append(searchaction(e)[4])
                listcategory.append(0)
          if line[5]=='Identification' and line[6]=='Network':
            for e in identificationnetwork:
              if len(searchaction(e))!=0 and searchaction(e)[0] not in listaction:
                listaction.append(searchaction(e)[0])
                listphase.append(2)
                listimpact.append(searchaction(e)[1])
                listcomplexity.append(searchaction(e)[2])
                listloss.append(searchaction(e)[3])
                listrequirement.append(searchaction(e)[4])
                listcategory.append(1)
          if line[5]=='Containment' and line[6]=='Network':
            #print(line[3], line[4], containmentnetwork)
            for e in containmentnetwork:
              #print(searchaction(e)[0])
              if len(searchaction(e))!=0 and searchaction(e)[0] not in listaction:
                listaction.append(searchaction(e)[0])
                listphase.append(3)
                listimpact.append(searchaction(e)[1])
                listcomplexity.append(searchaction(e)[2])
                listloss.append(searchaction(e)[3])
                listrequirement.append(searchaction(e)[4])
                listcategory.append(1)
              #print(searchaction(e))
          if line[5]=='Recovery' and line[6]=='Network':
            for e in recoverynetwork:
              #print(searchaction(e))
              if len(searchaction(e))!=0 and searchaction(e)[0] not in listaction:
                listaction.append(searchaction(e)[0])
                listphase.append(5)
                listimpact.append(searchaction(e)[1])
                listcomplexity.append(searchaction(e)[2])
                listloss.append(searchaction(e)[3])
                listrequirement.append(searchaction(e)[4])
                listcategory.append(1)
          if line[5]=='Preparation' and line[6]=='Network':
            for e in preparationnetwork:
              #print(searchaction(e))
              if len(searchaction(e))!=0 and searchaction(e)[0] not in listaction:
                listaction.append(searchaction(e)[0])
                listphase.append(1)
                listimpact.append(searchaction(e)[1])
                listcomplexity.append(searchaction(e)[2])
                listloss.append(searchaction(e)[3])
                listrequirement.append(searchaction(e)[4])
                listcategory.append(1)
          if line[5]=='Eradication' and line[6]=='Network':
            for e in eradicationnetwork:
              #print(searchaction(e))
              if len(searchaction(e))!=0 and searchaction(e)[0] not in listaction:
                listaction.append(searchaction(e)[0])
                listphase.append(4)
                listimpact.append(searchaction(e)[1])
                listcomplexity.append(searchaction(e)[2])
                listloss.append(searchaction(e)[3])
                listrequirement.append(searchaction(e)[4])
                listcategory.append(1)
          if line[5]=='Identification' and line[6]=='File':
            for e in identificationfile:
              if len(searchaction(e))!=0 and searchaction(e)[0] not in listaction:
                listaction.append(searchaction(e)[0])
                listphase.append(2)
                listimpact.append(searchaction(e)[1])
                listcomplexity.append(searchaction(e)[2])
                listloss.append(searchaction(e)[3])
                listrequirement.append(searchaction(e)[4])
                listcategory.append(3)
          if line[5]=='Containment' and line[6]=='File':
            for e in containmentfile:
              #print(searchaction(e))
              if len(searchaction(e))!=0 and searchaction(e)[0] not in listaction:
                listaction.append(searchaction(e)[0])
                listphase.append(3)
                listimpact.append(searchaction(e)[1])
                listcomplexity.append(searchaction(e)[2])
                listloss.append(searchaction(e)[3])
                listrequirement.append(searchaction(e)[4])
                listcategory.append(3)
          if line[5]=='Recovery' and line[6]=='File':
            for e in recoveryfile:
              #print(searchaction(e))
              if len(searchaction(e))!=0 and searchaction(e)[0] not in listaction:
                listaction.append(searchaction(e)[0])
                listphase.append(5)
                listimpact.append(searchaction(e)[1])
                listcomplexity.append(searchaction(e)[2])
                listloss.append(searchaction(e)[3])
                listrequirement.append(searchaction(e)[4])
                listcategory.append(3)
          if line[5]=='Preparation' and line[6]=='File':
            #print(preparationfile)
            for e in preparationfile:
              #print(searchaction(e))
              if len(searchaction(e))!=0 and searchaction(e)[0] not in listaction:
                listaction.append(searchaction(e)[0])
                listphase.append(1)
                listimpact.append(searchaction(e)[1])
                listcomplexity.append(searchaction(e)[2])
                listloss.append(searchaction(e)[3])
                listrequirement.append(searchaction(e)[4])
                listcategory.append(3)
          if line[5]=='Eradication' and line[6]=='File':
            for e in eradicationfile:
              #print(searchaction(e))
              if len(searchaction(e))!=0 and searchaction(e)[0] not in listaction:
                listaction.append(searchaction(e)[0])
                listphase.append(4)
                listimpact.append(searchaction(e)[1])
                listcomplexity.append(searchaction(e)[2])
                listloss.append(searchaction(e)[3])
                listrequirement.append(searchaction(e)[4])
                listcategory.append(3)
          if line[5]=='Identification' and line[6]=='Email':
            for e in identificationemail:
              #print(searchaction(e))
              if len(searchaction(e))!=0 and searchaction(e)[0] not in listaction:
                listaction.append(searchaction(e)[0])
                listphase.append(2)
                listimpact.append(searchaction(e)[1])
                listcomplexity.append(searchaction(e)[2])
                listloss.append(searchaction(e)[3])
                listrequirement.append(searchaction(e)[4])
                listcategory.append(2)
          if line[5]=='Containment' and line[6]=='Email':
            for e in containmentemail:
              #print(searchaction(e))
              if len(searchaction(e))!=0 and searchaction(e)[0] not in listaction:
                listaction.append(searchaction(e)[0])
                listphase.append(3)
                listimpact.append(searchaction(e)[1])
                listcomplexity.append(searchaction(e)[2])
                listloss.append(searchaction(e)[3])
                listrequirement.append(searchaction(e)[4])
                listcategory.append(2)
          if line[5]=='Recovery' and line[6]=='Email':
            for e in recoveryemail:
              #print(searchaction(e))
              if len(searchaction(e))!=0 and searchaction(e)[0] not in listaction:
                listaction.append(searchaction(e)[0])
                listphase.append(5)
                listimpact.append(searchaction(e)[1])
                listcomplexity.append(searchaction(e)[2])
                listloss.append(searchaction(e)[3])
                listrequirement.append(searchaction(e)[4])
                listcategory.append(2)
          if line[5]=='Preparation' and line[6]=='Email':
            for e in preparationemail:
              #print(searchaction(e))
              if len(searchaction(e))!=0 and searchaction(e)[0] not in listaction:
                listaction.append(searchaction(e)[0])
                listphase.append(1)
                listimpact.append(searchaction(e)[1])
                listcomplexity.append(searchaction(e)[2])
                listloss.append(searchaction(e)[3])
                listrequirement.append(searchaction(e)[4])
                listcategory.append(2)
          if line[5]=='Eradication' and line[6]=='Email':
            for e in eradicationemail:
              #print(searchaction(e))
              if len(searchaction(e))!=0 and searchaction(e)[0] not in listaction:
                listaction.append(searchaction(e)[0])
                listphase.append(4)
                listimpact.append(searchaction(e)[1])
                listcomplexity.append(searchaction(e)[2])
                listloss.append(searchaction(e)[3])
                listrequirement.append(searchaction(e)[4])
                listcategory.append(2)
          if line[5]=='Identification' and line[6]=='Configuration':
            for e in identificationconfiguration:
              #print(searchaction(e))
              if len(searchaction(e))!=0 and searchaction(e)[0] not in listaction:
                listaction.append(searchaction(e)[0])
                listphase.append(2)
                listimpact.append(searchaction(e)[1])
                listcomplexity.append(searchaction(e)[2])
                listloss.append(searchaction(e)[3])
                listrequirement.append(searchaction(e)[4])
                listcategory.append(5)
          if line[5]=='Containment' and line[6]=='Configuration':
            for e in containmentconfiguration:
              #print(searchaction(e))
              if len(searchaction(e))!=0 and searchaction(e)[0] not in listaction:
                listaction.append(searchaction(e)[0])
                listphase.append(3)
                listimpact.append(searchaction(e)[1])
                listcomplexity.append(searchaction(e)[2])
                listloss.append(searchaction(e)[3])
                listrequirement.append(searchaction(e)[4])
                listcategory.append(5)
          if line[5]=='Recovery' and line[6]=='Configuration':
            for e in recoveryconfiguration:
              #print(searchaction(e))
              if len(searchaction(e))!=0 and searchaction(e)[0] not in listaction:
                listaction.append(searchaction(e)[0])
                listphase.append(5)
                listimpact.append(searchaction(e)[1])
                listcomplexity.append(searchaction(e)[2])
                listloss.append(searchaction(e)[3])
                listrequirement.append(searchaction(e)[4])
                listcategory.append(5)
          if line[5]=='Preparation' and line[6]=='Configuration':
            for e in preparationconfiguration:
              #print(searchaction(e))
              if len(searchaction(e))!=0 and searchaction(e)[0] not in listaction:
                listaction.append(searchaction(e)[0])
                listphase.append(1)
                listimpact.append(searchaction(e)[1])
                listcomplexity.append(searchaction(e)[2])
                listloss.append(searchaction(e)[3])
                listrequirement.append(searchaction(e)[4])
                listcategory.append(5)
          if line[5]=='Eradication' and line[6]=='Configuration':
            for e in eradicationconfiguration:
              #print(searchaction(e))
              if len(searchaction(e))!=0 and searchaction(e)[0] not in listaction:
                listaction.append(searchaction(e)[0])
                listphase.append(4)
                listimpact.append(searchaction(e)[1])
                listcomplexity.append(searchaction(e)[2])
                listloss.append(searchaction(e)[3])
                listrequirement.append(searchaction(e)[4])
                listcategory.append(5)
          if line[5]=='Identification' and line[6]=='Identity':
            #print(identificationidentity)
            for e in containmentprocess:
              #print(searchaction(e))
              if len(searchaction(e))!=0 and searchaction(e)[0] not in listaction:
                listaction.append(searchaction(e)[0])
                listphase.append(2)
                listimpact.append(searchaction(e)[1])
                listcomplexity.append(searchaction(e)[2])
                listloss.append(searchaction(e)[3])
                listrequirement.append(searchaction(e)[4])
                listcategory.append(6)
          if line[5]=='Containment' and line[6]=='Identity':
            for e in containmentidentity:
              #print(searchaction(e))
              if len(searchaction(e))!=0 and searchaction(e)[0] not in listaction:
                listaction.append(searchaction(e)[0])
                listphase.append(3)
                listimpact.append(searchaction(e)[1])
                listcomplexity.append(searchaction(e)[2])
                listloss.append(searchaction(e)[3])
                listrequirement.append(searchaction(e)[4])
                listcategory.append(6)
          if line[5]=='Recovery' and line[6]=='Identity':
            for e in recoveryidentity:
              #print(searchaction(e))
              if len(searchaction(e))!=0 and searchaction(e)[0] not in listaction:
                listaction.append(searchaction(e)[0])
                listphase.append(5)
                listimpact.append(searchaction(e)[1])
                listcomplexity.append(searchaction(e)[2])
                listloss.append(searchaction(e)[3])
                listrequirement.append(searchaction(e)[4])
                listcategory.append(6)
          if line[5]=='Preparation' and line[6]=='Identity':
            for e in preparationidentity:
              #print(searchaction(e))
              if len(searchaction(e))!=0 and searchaction(e)[0] not in listaction:
                listaction.append(searchaction(e)[0])
                listphase.append(1)
                listimpact.append(searchaction(e)[1])
                listcomplexity.append(searchaction(e)[2])
                listloss.append(searchaction(e)[3])
                listrequirement.append(searchaction(e)[4])
                listcategory.append(6)
          if line[5]=='Eradication' and line[6]=='Identity':
            for e in eradicationidentity:
              #print(searchaction(e))
              if len(searchaction(e))!=0 and searchaction(e)[0] not in listaction:
                listaction.append(searchaction(e)[0])
                listphase.append(4)
                listimpact.append(searchaction(e)[1])
                listcomplexity.append(searchaction(e)[2])
                listloss.append(searchaction(e)[3])
                listrequirement.append(searchaction(e)[4])
                listcategory.append(6)
  return listaction, listphase, listimpact, listcomplexity, listloss, listrequirement, listcategory

def genplay(cve):
  # Record the start time
  start_time = time.time()
  

  my_world = World()
  my_world.get_ontology("/var/www/html/ADG/playbook.owl").load() #path to the owl file is given here
  #sync_reasoner(my_world)  #reasoner is started and synchronized here
  graph = my_world.as_rdflib_graph()

  file_n="/var/www/html/ADG/res7.tsv"
  actions=readtsv(cve,file_n)
  

  lst = [cve] * len(actions[0])

  if len(lst)!=0:
    playbook(cve, lst, actions[0], actions[5], actions[2], actions[3], actions[4], actions[1], actions[6])
    end_time = time.time()

    execution_time =  end_time-start_time
  else:
    print(cve)
    graphmatch.matchgraph(cve)
    # Record the start time
    start_time = time.time()
    

    my_world = World()
    my_world.get_ontology("/var/www/html/ADG/playbook.owl").load() #path to the owl file is given here
    #sync_reasoner(my_world)  #reasoner is started and synchronized here
    graph = my_world.as_rdflib_graph()

    file_n="/var/www/html/ADG/countermeasureexec.tsv"
    actions=readtsv(cve,file_n)   

    lst = [cve] * len(actions[0])
    playbook(cve, lst, actions[0], actions[5], actions[2], actions[3], actions[4], actions[1], actions[6])

    end_time = time.time()

    execution_time =  end_time-start_time
    """if len(max_impact_item)==3:
      with open(CVE+".txt", "a") as myfile:
          myfile.write(playbook1+'\n'+playbook2+'\n'+playbook3+'\n'+playbook3_2+'\n')
    if len(max_impact_item)==4:
      with open(CVE+".txt", "a") as myfile:
          myfile.write(playbook1+'\n'+playbook2+'\n'+playbook3+'\n'+playbook4+'\n'+playbook4_2+'\n')
    if len(max_impact_item)==5:
      with open(CVE+".txt", "a") as myfile:
          myfile.write(playbook1+'\n'+playbook2+'\n'+playbook3+'\n'+playbook4+'\n'+playbook5+'\n'+playbook5_2+'\n')
    if len(max_impact_item)==6:
      with open(CVE+".txt", "a") as myfile:
          myfile.write(playbook1+'\n'+playbook2+'\n'+playbook3+'\n'+playbook4+'\n'+playbook5+'\n'+playbook6+'\n'+playbook6_2+'\n')
    if len(max_impact_item)==7:
      with open(CVE+".txt", "a") as myfile:
          myfile.write(playbook1+'\n'+playbook2+'\n'+playbook3+'\n'+playbook4+'\n'+playbook5+'\n'+playbook6+'\n'+playbook7+'\n'+playbook7_2+'\n')"""