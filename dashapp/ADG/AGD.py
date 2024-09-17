import matplotlib
matplotlib.use('Agg') 
import dash
from dash import dcc, html, Input, Output, State
import plotly.express as px
import csv
import networkx as nx
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import scipy as sp
from math import *
from rdflib import Graph
import json
import base64
from io import BytesIO
import generateplaybook
import requestalerts
import re
import os
import time
import dash_cytoscape as cyto

def get_file_creation_time(file_path):
    # Get the file's status
    file_stats = os.stat(file_path)
    
    # Get the creation time
    creation_time = file_stats.st_ctime
    
    # Convert the timestamp to a human-readable format
    creation_time_human_readable = time.ctime(creation_time)
    
    return creation_time_human_readable

def csv_to_list_of_tuples(file_path):
    data_list = []
    with open(file_path, 'r') as file:
        csv_reader = csv.reader(file)
        for row in csv_reader:
            if row[-1] != '-1':
                # If last element is not -1, create tuple with first two elements
                row_tuple = (int(row[0]), int(row[1]))
            else:
                # If last element is -1, swap the order of the first and second elements
                row_tuple = (int(row[1]), int(row[0]))
            data_list.append(row_tuple)
    return data_list

def csv_to_list(file_path):
    data_list = []
    with open(file_path, 'r') as file:
        csv_reader = csv.reader(file)
        for row in csv_reader:
            # Convert the first element to int and exclude the last value
            row_data = [int(row[0])] + row[1:-1]
            data_list.append(row_data)
    return data_list

def generate_graph(arc,node):
    node_colors=[]
    colors=[]
    labels=[]
    pos=[]
    predicates=[]
    data=[]
    G_multilevel=[]
    result = csv_to_list_of_tuples(arc)
    data = csv_to_list(node)
    G = nx.DiGraph()

    predicates=data
    DF_predicates=pd.DataFrame(predicates,columns=['Nodes','Predicates','type'])
    # Add nodes and edges to the graph
    for row in data:
        node_id = row[0]
        node_label = row[1]
        node_type = row[2]
        G.add_node(node_id, label=node_label, typen=node_type)

    # Define node colors based on node types
    node_colors = {'LEAF': '#1fad3c', 'OR': '#15b0e8', 'AND': '#d10fb1', 'C':'#de5c0b'}
    colors = [node_colors[data[node][2]] for node in range(len(G.nodes()))]
    labels=nx.get_node_attributes(G,'label')
    G.add_edges_from(result)
    # determining the name of the file
    file_name = '/var/www/html/ADG/AGpredicates.xlsx'

    # saving the excel
    DF_predicates.to_excel(file_name)

    # Draw the graph
    pos = nx.spring_layout(G)

    adj_matrix = nx.adjacency_matrix(G)
    DF_adj = pd.DataFrame(adj_matrix.todense(),index=G.nodes(),columns=G.nodes())
    file_name = '/var/www/html/ADG/Adjmatrix.xlsx'

    # saving the excel
    DF_adj.to_excel(file_name)

    G_multilevel = nx.DiGraph()
    G_oriented=G
    # Traverse the nodes of the oriented graph
    for node in G_oriented.nodes():
        # Add the node to the multi-level graph
        G_multilevel.add_node(node)
        # Traverse the successors of the node in the oriented graph
        for successor in G_oriented.successors(node):
            # Check if the level of the successor has already been added to the multi-level graph
            if successor in G_multilevel[node]:
                # If yes, add the successor to the corresponding level
                G_multilevel[node][successor]["level"].append(successor)
            else:
                # Otherwise, create a new level for the successor and add it
                G_multilevel.add_edge(node, successor, level=[successor])
    
    
    return G,predicates,G_multilevel,node_colors,data,pos,colors,labels

def convert_to_flow_matrix(graph,net,act,predicates):
    num_nodes = graph.number_of_nodes()
    flow_matrix = np.zeros((num_nodes, num_nodes), dtype=int)
    predica= [predic[0] for predic in predicates if predic[1].startswith('vulExists')]
    located= [predic[0] for predic in predicates if predic[1].startswith('attackerLocated')]
    #print(net,act)
    for edge in graph.edges:
        source, target = edge
        if source in predica:
            #print(source,target)
            flow_matrix[source-1][target-1] = 1
        if source in located:
            #print(source,target)
            flow_matrix[source-1][target-1] = 1
        if source in net or source in act:
            flow_matrix[source-1][target-1] = 1
          #else:
            #if source==int(vul) or source==int(net) or source==int(act):
              #flow_matrix[source-1][target-1] = 1

    return flow_matrix

def remove_prefix(full_name):
    if full_name.startswith("http://kevin.abouahmed/IncidentResponseOntologyPlaybook#"):
        #return full_name.removeprefix("http://kevin.abouahmed/IncidentResponseOntologyPlaybook#")
        return full_name.split("http://kevin.abouahmed/IncidentResponseOntologyPlaybook#")[1]
    else:
        #print(full_name)
        return full_name

def get_vulname(graph,predicates):
    num_nodes = graph.number_of_nodes()
    flow_matrix = np.zeros((num_nodes, num_nodes), dtype=int)
    #predica= [predic[0] for predic in predicates if predic[1].startswith('vulExists')]
    vuls=[predic[1] for predic in predicates if predic[1].startswith('vulExists')]

    return vuls

def get_first_step(onto,playbook_name):
    first_step = ""

    query = """
    PREFIX :<http://kevin.abouahmed/IncidentResponseOntologyPlaybook#>
    SELECT ?first_step
    WHERE {
        ?playbook a :Playbook .
        ?playbook rdfs:label "%s" .
        ?playbook :has_coa ?step .
        ?step rdfs:label ?first_step .
        }
    """%playbook_name

    qres = onto.query(query)
    for i in qres:
       first_step = remove_prefix(i.first_step)

    return first_step

def get_action_from_step(onto, step):
    action_name = ""

    query = """
    PREFIX :<http://kevin.abouahmed/IncidentResponseOntologyPlaybook#>
    PREFIX uco: <https://ontology.unifiedcyberontology.org/uco/action/Action#>
    SELECT ?action
    WHERE {
        ?action a uco:Action .
        ?step rdfs:label "%s" .
        ?step :is_action ?action .
        }
    """%step

    qres = onto.query(query)
    for i in qres:
        action_name = remove_prefix(i.action)

    return action_name

def get_next_step(onto,current_step):
    next_step = ""

    query = """
    PREFIX :<http://kevin.abouahmed/IncidentResponseOntologyPlaybook#>

    SELECT ?next_step
    WHERE {
        ?step rdfs:label "%s" .
        ?step :has_next ?next_step .
        }
    """%current_step

    qres = onto.query(query)
    for i in qres:
        next_step = remove_prefix(i.next_step)

    return next_step

def get_parallel_step(onto,current_step):
    next_step = ""

    query = """
    PREFIX :<http://kevin.abouahmed/IncidentResponseOntologyPlaybook#>

    SELECT ?next_step
    WHERE {
        ?step rdfs:label "%s" .
        ?step :parallel ?next_step .
        }
    """%current_step

    qres = onto.query(query)
    for i in qres:
        next_step = remove_prefix(i.next_step)

    return next_step

def get_next_step_if_true(onto,current_step):
    next_step = ""

    query = """
    PREFIX :<http://kevin.abouahmed/IncidentResponseOntologyPlaybook#>

    SELECT ?next_step
    WHERE {
        ?step rdfs:label "%s" .
        ?step :has_next_if_true ?next_step .
        }
    """%current_step

    qres = onto.query(query)
    for i in qres:
        next_step = remove_prefix(i.next_step)

    return next_step


def get_next_step_if_false(onto,current_step):
    next_step = ""

    query = """
    PREFIX :<http://kevin.abouahmed/IncidentResponseOntologyPlaybook#>
    PREFIX uco: <https://ontology.unifiedcyberontology.org/uco/action/Action#>

    SELECT ?next_step
    WHERE {
        ?step rdfs:label "%s" .
        ?step :has_next_if_false ?next_step .
        }
    """%current_step

    qres = onto.query(query)
    for i in qres:
        next_step = remove_prefix(i.next_step)

    return next_step

def iterate_coa(onto,current_step):

    next_step = get_next_step(onto, current_step)
    if next_step != "":
        iterate_coa(onto,next_step)
        return get_action_from_step(onto,next_step), next_step
    else:
      next_step = get_parallel_step(onto, current_step)
      if next_step != "":
        iterate_coa(onto,next_step)
        return get_action_from_step(onto,next_step), next_step
      else:
          next_step = get_next_step_if_true(onto, current_step)
          if next_step != "":
              iterate_coa(onto,next_step)
              return get_action_from_step(onto,next_step), next_step

          next_step = get_next_step_if_false(onto, current_step)
          if next_step != "":
              iterate_coa(onto,next_step)
              return get_action_from_step(onto,next_step), next_step

    return "",""

def get_playbook_course_of_action(onto,playbook_name):
    coa = []
    condition = 0

    #Get the first step and action
    current_step = get_first_step(onto,playbook_name)
    coa.append(get_action_from_step(onto,current_step))

    action_name, current_step = iterate_coa(onto,current_step)
    while current_step != "":
        coa.append(action_name)
        action_name, current_step = iterate_coa(onto,current_step)

    return coa
def are_elements_in_column(df,column_name,elements):
    return all(element in df[column_name].values for element in elements)
def find_play_list(G,predicates):
    cont=pd.read_excel('/var/www/html/ADG/countermeasures.xlsx', engine='openpyxl')

    filename = "play.owl"
    path = "/var/www/html/ADG/" + filename
    vulner=get_vulname(G,predicates)
    #print(vulner)
    playbooks=[]
    list_vul=[]
    for v in vulner:
        vul=v.split(',')[1]
        # Define the regex pattern for CVE identifiers
        cve_pattern = r'CVE-\d{4}-\d{4,7}'
        #print(vul)
        # Use re.findall to find all occurrences of the pattern in the text
        #cve_identifiers = re.findall(cve_pattern, vul.split("'")[1])
        cve_identifiers=re.findall(cve_pattern, vul)
        if len(cve_identifiers)!=0:
            list_vul.append(cve_identifiers[0])
    
    if all(element in list_vul for element in cont['CVE'])==True and len(cont['CVE'])!=0:
            #print(cont)
            countermeasure_list=pd.read_excel('/var/www/html/ADG/countermeasures.xlsx', engine='openpyxl')
    else:
        for v in vulner:

            vul=v.split(',')[1]
            #print(vul)
            # Define the regex pattern for CVE identifiers
            cve_pattern = r'CVE-\d{4}-\d{4,7}'

            # Use re.findall to find all occurrences of the pattern in the text
            #cve_identifiers = re.findall(cve_pattern, vul.split("'")[1])
            cve_identifiers=re.findall(cve_pattern, vul)
            if len(cve_identifiers)!=0:
                ontology = Graph()
                ontology.parse(path, format="ttl")

                #print("Playbook : Response to "+vul.split("'")[1]+".")
                jsonplay={}
                playbook=get_playbook_course_of_action(ontology,"Playbook : Response to "+vul.split("'")[1])
                lent=len(playbook)
                if lent==1:
                    if playbook[0]=="":
                        for predic in predicates:
                            if predic[1].startswith('vulExists'):
                                if str(predic[1].split('(')[1].split(',')[1])==vul:
                                    cve_file="/var/www/html/ADG/"+vul.split("'")[1]+".json"
                                    vulname=vul
                                    pos=predic[1].split('(')[1].split(',')[3].split('Exploit')[0]
                                    equip=predic[1].split('(')[1].split(',')[2]
                                    #print(cve_file,vulname,pos,equip)
                                    jsoncve={
                                        "Vulnerability":vulname,
                                        "Position":pos,
                                        "Equipement":equip,
                                    }
                                    #print(cve_file)
                                    with open(cve_file, 'w') as file:
                                        json.dump(jsoncve, file, indent=4)
                                        #print(vul)
                                    generateplaybook.genplay(vul.split("'")[1])
                                    ontology2 = Graph()
                                    ontology2.parse(path, format="ttl")
                                    playbook=get_playbook_course_of_action(ontology2,"Playbook : Response to "+vul.split("'")[1])
                jsonplay={"CVE":vul,"Playbook":playbook}
                playbooks.append(jsonplay)
                #for l in listID:
        #print(playbooks)
        c=0
        # determining the name of the file
        file_name = '/var/www/html/ADG/predicatesTable.xlsx'

        # saving the excel
        DF_predcont = pd.read_excel(file_name)

        IDCount=DF_predcont['ID']
        #print(IDCount)
        listID=IDCount.values.tolist()
        #print(listID)
        countermeasures=[]
        attackpredicates=[]
        cid=[]
        vulid=[]
        filtered_df=pd.DataFrame()
        for play in playbooks:
            for p in play['Playbook']:
                if p!='':
                    counter = DF_predcont[DF_predcont['ID'].apply(lambda x: p in x)]
                    #result = DF_predcont[IDCount.str.contains(p)]['Countermeasures Predicates']
                    # Remove empty rows
                    #filtered_df = filtered_df.dropna()
                    if len(counter)!=0:
                        for i in range(len(counter)):
                            print(counter['Countermeasures Predicates'].values[i])
                            print(len(counter))
                            countermeasures.append(counter['Countermeasures Predicates'].values[i])
                            attackpredicates.append(counter['Attack Predicates'].values[i])
                            c=c+1
                            counterid='C'+str(c)
                            cid.append(counterid)
                            vulid.append(play['CVE'].split("'")[1])
                        #print(counterid)

        countermeasure_list = pd.DataFrame(
            {'Name': cid,
            'CVE': vulid,
            'Countermeasures': countermeasures,
            'Predicates':attackpredicates
            })
        # determining the name of the file
        file_name = '/var/www/html/ADG/countermeasures.xlsx'
        print(countermeasure_list)
        # saving the excel
        #print(countermeasure_list)
        countermeasure_list.to_excel(file_name)
    return countermeasure_list



def update_to_flow_matrix(cond, graph,matrix,noeud,net,act,predicates):
    num_nodes = graph.number_of_nodes()
    preds=list(graph.predecessors(noeud))
    predica= [predic[0] for predic in predicates if predic[1]!='vulExists']
    netsolved=0
    actsolved=0
    if cond==1:
      for edge in graph.edges:
        source, target = edge
        for p in preds:
          if source==p and target==noeud:
            matrix[source-1][target-1] = 0
            if p in net:
                net.remove(p)
                netsolved=p
            if p in act:
                act.remove(p)
                actsolved=p
    else:
      for edge in graph.edges:
        source, target = edge
        for p in preds:
          if source==p and target==noeud and p in predica:
            matrix[source-1][target-1] = 0
            if p in net:
                net.remove(p)
                netsolved=p
            if p in act:
                act.remove(p)
                actsolved=p
    return matrix, netsolved, actsolved

vectorlist=[]
def extract_nonzero_vectors(flow_matrix):
    nonzero_vectors = []

    for col_index, column in enumerate(zip(*flow_matrix)):
        if any(value != 0 for value in column):
            vector = [row[col_index] for row in flow_matrix]
            nonzero_vectors.append((vector, col_index))

    return nonzero_vectors

def pred_and_succ(G_multilevel):
    occurencecount=[]
    multilevel_graph = G_multilevel.edges(data=True)

    level_counts = {}

    for edge in multilevel_graph:
        levels = edge[2]['level']

        for level in levels:
            if level in level_counts:
                level_counts[level] += 1
            else:
                level_counts[level] = 1

    # Display the result
    for level, count in level_counts.items():
        occurencecount.append({'Level':level,'occurrence':count})
    successors_count = {}
    for node in G_multilevel.nodes():
        successors_count[node] = len(list(nx.dfs_edges(G_multilevel, source=node)))
    # Calculate number of predecessors for each node
    predecessors_count = dict(G_multilevel.in_degree())
    return occurencecount,successors_count,predecessors_count

def get_flow_value(flow_matrix, from_node, to_node):
    # Check if the nodes are within the matrix bounds
    if from_node < 0 or from_node >= len(flow_matrix) or to_node < 0 or to_node >= len(flow_matrix[0]):
        return None  # Nodes are out of bounds

    # Access the flow value between the two nodes in the flow matrix
    flow_value = flow_matrix[from_node][to_node]

    return flow_value
def take_alerts(fichier):
    # Load the Excel file
    excel_file = fichier
    df = pd.read_excel(excel_file, engine='openpyxl')

    # Iterate over each column and convert it into an array
    arrays = []
    for column in df.columns:
        arrays.append(df[column].values)
    return arrays
# Draw the graph using Matplotlib
def get_position_of_sublist(main_list, target_value):
    for index, sublist in enumerate(main_list):
        if sublist[0] == target_value:
            return index
    return -1
def create_graph(G, pos,colors,labels,node_colors,data):
    #print(len(data))
    #print(len(colors))
    #print(len(G.nodes()))
    #print(len(G.edges()))
    elements = []
    
    for node in G.nodes():
        #print(node_colors,data[get_position_of_sublist(data,node)][2],get_position_of_sublist(data,node),node,data[get_position_of_sublist(data,node)])
        col=node_colors[data[get_position_of_sublist(data,node)][2]]
        type_n=data[get_position_of_sublist(data,node)][2]
        if type(node)==int:
            print(col,labels[node])
            elements.append({
                'data': {'id': str(node), 'label': str(labels[node]), 'type':type_n}
            })
        else:
            elements.append({
                'data': {'id': str(node), 'label': str(node), 'type':type_n}
            })
    for edge in G.edges():
        #print(edge)
        elements.append({'data': {'source': str(edge[0]), 'target': str(edge[1])}})
    print(elements)
    return elements

def enrich_graph(G,predicates,countermeasure_list,occurencecount,successors_count,predecessors_count,net,act):
    t=0
    v_t=1

    #act=15
    #print(act,net)
    print(net,act)

    new_G = nx.DiGraph()
    vectorlist2=[]
    # Convert the graph to a flow matrix
    flow_matrix = convert_to_flow_matrix(G,net,act,predicates)
    DF_flow = pd.DataFrame(flow_matrix, index=range(1, flow_matrix.shape[0] + 1), columns=range(1, flow_matrix.shape[1] + 1))
    
    # determining the name of the file
    file_name = '/var/www/html/ADG/Flowmatrix.xlsx'
    # saving the excel
    DF_flow.to_excel(file_name)
    #while t<10:
    old_edges=list(G.edges())
    old_nodes=list(G.nodes())
    vectorlist=[]
    new_edges=[]
    new_nodes=[]
    nets,acts=[],[]
    result = extract_nonzero_vectors(flow_matrix)
    # Display the result
    for vector, col_index in result:
        vector_sum = sum(vector)
        vectorlist.append({'vector':vector_sum,'node':col_index+1})
    gen = (x for x in G.nodes() if predecessors_count[x]!=0)
    for j in gen:
        level_occurrence = next(item['occurrence'] for item in occurencecount if item['Level'] == j)
        vector_value=next((item['vector'] for item in vectorlist if item['node'] == j), 0)
        if vector_value == level_occurrence:
            successors_V=list(G.successors(j))
            for l in successors_V:
                if j<len(predicates):
                    pred=predicates[l-1]
                #for pred in predicates:
                    if pred[2]!='AND' and pred[0]==l and len(list(G.successors(l)))>0:
                        #if pred[0]==l:
                            #print(pred[1])
                        for counter in range(len(countermeasure_list['Predicates'])):
                            #print(counter)
                            if pred[1].split('(')[0]==countermeasure_list['Predicates'][counter].split('(')[0]:
                                contpred=countermeasure_list['Countermeasures'][counter].split('(')[0]
                                if contpred.startswith('patch'):
                                    vulide=pred[1].split('(')[1].split(',')[1]
                                    # Define the regex pattern for CVE identifiers
                                    cve_pattern = r'CVE-\d{4}-\d{4,7}'
                                    #print(vul)
                                    # Use re.findall to find all occurrences of the pattern in the text
                                    #cve_identifiers = re.findall(cve_pattern, vul.split("'")[1])
                                    cve_identifiers=re.findall(cve_pattern, vulide)
                                    if len(cve_identifiers)!=0 and str(pred[1].split('(')[1].split(',')[1]).split("'")[1]==countermeasure_list['CVE'][counter]:
                                        listpredparam=pred[1].split('(')[1].split(')')[0].split(',')
                                        listcontrparam=countermeasure_list['Countermeasures'][counter].split('(')[1].split(')')[0].split(',')
                                        #if counter[0]==pred[1]:
                                        for i in range(len(listcontrparam)):
                                            listcontrparam[i]=listpredparam[i]
                                        countermeasure=str(countermeasure_list['Countermeasures'][counter].split('(')[0])+'('+', '.join(listcontrparam)+')'
                                        nodenbr=str(pred[0])
                                        #counterm=countermeasure+'('+nodenbr+')'
                                        counterm=countermeasure
                                        new_nodes.append(counterm)
                                        new_edges.append((counterm, pred[0]))
                                        predecesseur=list(G.predecessors(j))
                                if contpred.startswith('unblock') or contpred.startswith('restore') or contpred.startswith('enable'):
                                    #print(get_vulname(G))
                                    cont=list(countermeasure_list.loc[countermeasure_list['Countermeasures'] == 'patchVul(_host, _vulID, _program)', 'CVE'])
                                    #commonlist=[x for x in countermeasure_list['CVE'] if x in ]
                                    notinplay=[x.split('(')[1].split(',')[1].split("'")[1] for x in get_vulname(G,predicates) if x.split('(')[1].split(',')[1].split("'")[1] not in cont]
                                    if len(notinplay)==0:
                                        listpredparam=pred[1].split('(')[1].split(')')[0].split(',')
                                        listcontrparam=countermeasure_list['Countermeasures'][counter].split('(')[1].split(')')[0].split(',')
                                        #if counter[0]==pred[1]:
                                        for i in range(len(listcontrparam)):
                                            listcontrparam[i]=listpredparam[i]
                                        countermeasure=str(countermeasure_list['Countermeasures'][counter].split('(')[0])+'('+', '.join(listcontrparam)+')'
                                        nodenbr=str(pred[0])
                                        #counterm=countermveasure+'('+nodenbr+')'
                                        counterm=countermeasure
                                        new_nodes.append(counterm)
                                        new_edges.append((counterm, pred[0]))
                                        predecesseur=list(G.predecessors(j))
                                        #for predi in predecesseur:
                                if contpred.startswith('find') or contpred.startswith('list') or contpred.startswith('block') or contpred.startswith('disable'):
                                    listpredparam=pred[1].split('(')[1].split(')')[0].split(',')
                                    listcontrparam=countermeasure_list['Countermeasures'][counter].split('(')[1].split(')')[0].split(',')
                                    #if counter[0]==pred[1]:
                                    for i in range(len(listcontrparam)):
                                        listcontrparam[i]=listpredparam[i]
                                    countermeasure=str(countermeasure_list['Countermeasures'][counter].split('(')[0])+'('+', '.join(listcontrparam)+')'
                                    nodenbr=str(pred[0])
                                    #counterm=countermeasure+'('+nodenbr+')'
                                    counterm=countermeasure
                                    new_nodes.append(counterm)
                                    new_edges.append((counterm, pred[0]))
                                    predecesseur=list(G.predecessors(j))
                                    #for predi in predecesseur:
            resconvert=update_to_flow_matrix(0,G,flow_matrix,j,net,act,predicates)
            flow_matrix=resconvert[0] 
            nets.append(resconvert[1])
            acts.append(resconvert[2])
            #acts.append[resconvert[2]]
            DF_flow = pd.DataFrame(flow_matrix, index=range(1, flow_matrix.shape[0] + 1), columns=range(1, flow_matrix.shape[1] + 1))
            #display(DF_flow)
            #print(net,act)
        if vector_value < level_occurrence and vector_value>0:
            predecessors_V=list(G.predecessors(j))
            for k in predecessors_V:
                flow_value_between_nodes = get_flow_value(flow_matrix, k-1, j-1)
                if flow_value_between_nodes==1:
                    #if j<len(predicates):
                    pred=predicates[k-1]
                    #for pred in predicates:
                    if pred[2]!='AND' and pred[0]==k:
                            #if pred[0]==k:
                            #print(countermeasure_list['Predicates'])
                        for counter in range(len(countermeasure_list['Predicates'])):       
                            #print(countermeasure_list['Predicates'][counter])                         
                            if pred[1].split('(')[0]==countermeasure_list['Predicates'][counter].split('(')[0]:
                                #print(pred[1])
                                contpred=countermeasure_list['Countermeasures'][counter].split('(')[0]
                                #print(contpred)
                                if contpred.startswith('patch'):
                                    vulide=pred[1].split('(')[1].split(',')[1]
                                    # Define the regex pattern for CVE identifiers
                                    cve_pattern = r'CVE-\d{4}-\d{4,7}'
                                    #print(vul)
                                    # Use re.findall to find all occurrences of the pattern in the text
                                    #cve_identifiers = re.findall(cve_pattern, vul.split("'")[1])
                                    cve_identifiers=re.findall(cve_pattern, vulide)
                                    if len(cve_identifiers)!=0 and str(pred[1].split('(')[1].split(',')[1]).split("'")[1]==countermeasure_list['CVE'][counter]:
                                        listpredparam=pred[1].split('(')[1].split(')')[0].split(',')
                                        listcontrparam=countermeasure_list['Countermeasures'][counter].split('(')[1].split(')')[0].split(',')
                                        #if counter[0]==pred[1]:
                                        for i in range(len(listcontrparam)):
                                            listcontrparam[i]=listpredparam[i]
                                        countermeasure=str(countermeasure_list['Countermeasures'][counter].split('(')[0])+'('+', '.join(listcontrparam)+')'
                                        nodenbr=str(pred[0])
                                        #counterm=countermeasure+'('+nodenbr+')'
                                        counterm=countermeasure
                                        new_nodes.append(counterm)
                                        new_edges.append((counterm, pred[0]))
                                        predecesseur=list(G.predecessors(j))
                                if contpred.startswith('unblock') or contpred.startswith('restore') or contpred.startswith('enable'):
                                    cont=list(countermeasure_list.loc[countermeasure_list['Countermeasures'] == 'patchVul(_host, _vulID, _program)', 'CVE'])
                                    #commonlist=[x for x in countermeasure_list['CVE'] if x in ]
                                    notinplay=[x.split('(')[1].split(',')[1].split("'")[1] for x in get_vulname(G,predicates) if x.split('(')[1].split(',')[1].split("'")[1] not in cont]
                                    #print(cont)
                                    if len(notinplay)==0:
                                        listpredparam=pred[1].split('(')[1].split(')')[0].split(',')
                                        listcontrparam=countermeasure_list['Countermeasures'][counter].split('(')[1].split(')')[0].split(',')
                                        #if counter[0]==pred[1]:
                                        for i in range(len(listcontrparam)):
                                            listcontrparam[i]=listpredparam[i]
                                        countermeasure=str(countermeasure_list['Countermeasures'][counter].split('(')[0])+'('+', '.join(listcontrparam)+')'
                                        nodenbr=str(pred[0])
                                        #counterm=countermeasure+'('+nodenbr+')'
                                        counterm=countermeasure
                                        new_nodes.append(counterm)
                                        new_edges.append((counterm, pred[0]))
                                        predecesseur=list(G.predecessors(j))
                                        #for predi in predecesseur:
                                if contpred.startswith('find') or contpred.startswith('list') or contpred.startswith('block') or contpred.startswith('disable'):
                                    listpredparam=pred[1].split('(')[1].split(')')[0].split(',')
                                    listcontrparam=countermeasure_list['Countermeasures'][counter].split('(')[1].split(')')[0].split(',')
                                    #if counter[0]==pred[1]:
                                    for i in range(len(listcontrparam)):
                                        listcontrparam[i]=listpredparam[i]
                                    countermeasure=str(countermeasure_list['Countermeasures'][counter].split('(')[0])+'('+', '.join(listcontrparam)+')'
                                    nodenbr=str(pred[0])
                                    #counterm=countermeasure+'('+nodenbr+')'
                                    counterm=countermeasure
                                    new_nodes.append(counterm)
                                    new_edges.append((counterm, pred[0]))
                                    predecesseur=list(G.predecessors(j))
                                    #for predi in predecesseur:
            resconvert=update_to_flow_matrix(0,G,flow_matrix,j,net,act,predicates)
            flow_matrix=resconvert[0]
            DF_flow = pd.DataFrame(flow_matrix, index=range(1, flow_matrix.shape[0] + 1), columns=range(1, flow_matrix.shape[1] + 1))
            #display(DF_flow)
        if len(new_nodes)!=0:
            #print(t,old_nodes,new_nodes,vector_value,vectorlist,j)
            #print(len(colors))
            new_G.add_nodes_from(old_nodes)
            new_G.add_nodes_from(new_nodes)
            new_G.add_edges_from(old_edges)
            new_G.add_edges_from(new_edges)
        else:
            new_G.add_nodes_from(old_nodes)
            new_G.add_edges_from(old_edges)
    return new_G, nets, acts, DF_flow  

file_path,csv_file=[],[]
G,predicates,G_multilevel,node_colors,data,pos,colors,labels=nx.DiGraph(),[],[],[],[],[],[],[]
occcount, succ, pred=[],[],[]
countermeasures_list=[]
#val=False
# Example usage:
file_path = '/var/www/html/scriptphp/ARCS.CSV'  # Change this to your CSV file path
# Example usage
csv_file = '/var/www/html/scriptphp/VERTICES.CSV'  # Replace 'data.csv' with your CSV file name
G,predicates,G_multilevel,node_colors,data,pos,colors,labels=generate_graph(file_path,csv_file)
#print(G)

occcount, succ, pred=pred_and_succ(G_multilevel)
#print(occcount)
countermeasures_list=find_play_list(G,predicates)
#print(checknewalert)
#val=True
#elements=create_graph(G,pos,colors,labels,node_colors,data)
# Initialize the Dash app
app = dash.Dash(__name__)
# Define the app layout
app.layout = html.Div([
    html.H1("Attack Defense Graph"),
    cyto.Cytoscape(
        id='cytoscape-graph',
        layout={'name': 'cose'},
        style={'width': '100%', 'height': '600px'},
        #elements=create_graph(G,pos,colors,labels,node_colors,data),
        elements=[],
        stylesheet=[
            {
                'selector': 'node',
                'style': {
                    'label': 'data(label)',
                    'text-opacity': 0,
                    'width': '20px',
                    'height': '20px',
                    'font-size': '12px'
                }
            },
            {
                'selector': 'edge',
                'style': {
                    'mid-target-arrow-shape': 'triangle',
                    'arrow-scale': 2,
                    'line-color': 'gray',
                    'target-arrow-color': 'gray'
                }
            },
            {
                'selector':'node[type="LEAF"]',
                'style':{
                    'background-color':'#1fad3c'
                }
            },
             {
                'selector':'node[type="OR"]',
                'style':{
                    'background-color':'#15b0e8'
                }
            },
             {
                'selector':'node[type="AND"]',
                'style':{
                    'background-color':'#d10fb1'
                }
            },
             {
                'selector':'node[type="C"]',
                'style':{
                    'background-color':'#de5c0b'
                }
            }
        ]
    ),
    dcc.Interval(
        id='interval-component',
        interval=50*1000,  # in milliseconds (5000ms = 5s)
        n_intervals=0
    ),
    html.Div(id='node-data')
])

# Callback to update the graph periodically
@app.callback(
    Output('cytoscape-graph', 'elements'),
    [Input('interval-component', 'n_intervals')]
)

def update_graph(n_intervals):  
    file_path,csv_file=[],[]
    G,predicates,G_multilevel,node_colors,data,pos,colors,labels=nx.DiGraph(),[],[],[],[],[],[],[]
    occcount, succ, pred=[],[],[]
    countermeasures_list=[]
    #val=False
    # Example usage:
    file_path = '/var/www/html/scriptphp/ARCS.CSV'  # Change this to your CSV file path
    # Example usage
    csv_file = '/var/www/html/scriptphp/VERTICES.CSV'  # Replace 'data.csv' with your CSV file name
    G,predicates,G_multilevel,node_colors,data,pos,colors,labels=generate_graph(file_path,csv_file)
    #print(G)
    timegen=get_file_creation_time(file_path)
    requestalerts.alerts()
    checknewalert=take_alerts('/var/www/html/ADG/alerts.xlsx')
    net=list(checknewalert[0])
    #net=19
    act=list(checknewalert[1])
    #print(n_intervals)
    if len(checknewalert[0])!=0 or len(checknewalert[1])!=0:
            for i in range(len(checknewalert)):
                checknewalert[i][np.isnan(checknewalert[i])] = int(0)
    #img_src = create_graph(G,pos,colors)
    occcount, succ, pred=pred_and_succ(G_multilevel)

    #print(occcount)
    #countermeasures_list=find_play_list(G,predicates)
    #print(checknewalert)
    if len(checknewalert[1])==0 and len(checknewalert[0])==0 :
            n_intervals=0
            countermeasures_list=find_play_list(G,predicates)
            val=True
    else:
        nets_equality_comparison = set(G[1])==set(list(checknewalert)[0])
        acts_equality_comparison= set(G[2])==set(list(checknewalert)[1])
        if nets_equality_comparison==False or acts_equality_comparison==False:
            flow_matrix = convert_to_flow_matrix(G,list(checknewalert[0]),list(checknewalert[1]),predicates)
            DF_flow = pd.DataFrame(flow_matrix, index=range(1, flow_matrix.shape[0] + 1), columns=range(1, flow_matrix.shape[1] + 1))
            #print(DF_flow)
            n_intervals=0
            countermeasures_list=find_play_list(G,predicates)
            val=True
        else:
            val=False
    if n_intervals is None:
        #print("ok")
        raise dash.exceptions.PreventUpdatew
    #print(val)
    #print(G)
    #print(n_intervals,val)
    up_G=[]
    new_G=[]
    new_colors = []
    datanew=[]
    print(val,n_intervals)
    print(countermeasures_list)
    if val==True:
        up_G=[]
        new_G=[]
        new_colors = []
        datanew=[]
        #print(timegen)
        print(len(net),len(act))
        if len(net)!=0 or len(act)!=0:
            print(countermeasures_list)
            up_G =enrich_graph(G,predicates,countermeasures_list,occcount,succ,pred,net,act)
        else:
            countermeasures_list = pd.DataFrame(
            {'Name': [],
            'CVE': [],
            'Countermeasures': [],
            'Predicates': []
            })
            print(countermeasures_list)
            up_G =enrich_graph(G,predicates,countermeasures_list,occcount,succ,pred,net,act)
        requestalerts.alerts()
        # determining the name of the file
        file_name = '/var/www/html/ADG/Flowmatrix2.xlsx'
        # saving the excel
        up_G[3].to_excel(file_name)

        new_G=up_G[0]
        print(new_G)
        checknewalert=take_alerts('/var/www/html/ADG/alerts.xlsx')
        net=list(checknewalert[0])
        #net=19
        act=list(checknewalert[1])
        #print(len(checknewalert[0]))
        if len(checknewalert[0])!=0 or len(checknewalert[1])!=0:
            for i in range(len(checknewalert)):
                checknewalert[i][np.isnan(checknewalert[i])] = int(0)
        nets_equality_comparison = set(up_G[1])==set(list(checknewalert)[0])
        #print(up_G[1],up_G[2])
        #print(checknewalert)
        acts_equality_comparison= set(up_G[2])==set(list(checknewalert)[1])
        #print(acts_equality_comparison)
        #print(nets_equality_comparison)
        # Check if the matrix is a zero matrix
        
        """if nets_equality_comparison==False or acts_equality_comparison==False:
            flow_matrix = convert_to_flow_matrix(G,list(checknewalert[0]),list(checknewalert[1]),predicates)
            DF_flow = pd.DataFrame(flow_matrix, index=range(1, flow_matrix.shape[0] + 1), columns=range(1, flow_matrix.shape[1] + 1))
            #print(DF_flow)
            val=True
        else:
            flow_matrix = convert_to_flow_matrix(G,list(checknewalert[0]),list(checknewalert[1]),predicates)
            DF_flow = pd.DataFrame(flow_matrix, index=range(1, flow_matrix.shape[0] + 1), columns=range(1, flow_matrix.shape[1] + 1))
            #print(DF_flow)
            #val=False"""
        for  node in new_G.nodes():
            if isinstance(node, str):
                n=[node, node, 'C']
                datanew.append(n)
                #dt=data[node-1]
                #new_colors.append(node_colors[dt[2]])
                #datanew.append(data[node-1])
            #else:
                #n=[node, node, 'C']
                #datanew.append(n)
                #new_colors.append('#de5c0b')
        # Draw the graph with node colors
        #print(datanew)
        #print(len(new_G.nodes()))
        new_colors = [node_colors[data[node][2]] for node in range(len(G.nodes()))]
        
        #print(new_colors)
        for node in range(len(datanew)):
            new_colors.append(node_colors[datanew[node][2]])
        for node in range(len(data)):
            datanew.append(data[node])
        #print(new_colors)
        pos = nx.spring_layout(new_G, k=0.3)
        is_zero_matrix = np.all(up_G[3] == 0)
        if is_zero_matrix==True:
            #print(is_zero_matrix)
            val=False
        else:
            val=True
        #img_src = create_graph(new_G,pos,new_colors,labels,node_colors,datanew)
        #print(img_src)
        return create_graph(new_G,pos,new_colors,labels,node_colors,datanew)
    else:
        # Return the same image if no update is needed
        #print(val)
        return dash.no_update
    return create_graph(G,pos,colors,labels,node_colors,data)
# Callback to display node data on click
@app.callback(
    Output('node-data', 'children'),
    [Input('cytoscape-graph', 'tapNodeData')]
)
def display_node_data(data):
    if data:
        return f"{data['label']}"
    return "Click on a node to see its data."
if __name__ == '__main__':
    app.run_server(debug=True, host='0.0.0.0', port=8050)
