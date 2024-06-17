import pandas as pd
import spacy
# Import writer class from csv module
import csv
#SPARQL Query to the Playbook Standardisation Ontology
from owlready2 import *
my_world = World()
my_world.get_ontology("playbook.owl").load() #path to the owl file is given here
#sync_reasoner(my_world)  #reasoner is started and synchronized here
graph = my_world.as_rdflib_graph()

def searchaction():
    reactid=[]
    actions=[]
    labels=[]
    comments=[]
    sparql = """select ?action ?id ?label ?comment where{
                      ?action <http://kevin.abouahmed/IncidentResponseOntologyPlaybook#react-id> ?id .
                      ?action <http://www.w3.org/2000/01/rdf-schema#label> ?label .
                      ?action <http://www.w3.org/2000/01/rdf-schema#comment> ?comment .
                }"""
    #query is being run
    resultsList = graph.query(sparql)
    for row in resultsList:
        s = str(row['id'].toPython())
        x = str(row['action'].toPython())
        e = str(row['label'].toPython())
        v = str(row['comment'].toPython())

        reactid.append(s)
        actions.append(x)
        labels.append(e)
        comments.append(v)
    return reactid, actions, labels, comments
listactions=searchaction()
# Define the path to the pre-trained spaCy model
model_path = "pos_tagger_model"

def load_spacy_model(model_path):
    """Load the spaCy model from disk."""
    try:
        nlp = spacy.load(model_path)
        print("Loaded model '{}' from disk.".format(model_path))
        return nlp
    except IOError:
        print("Error: Model '{}' not found.".format(model_path))
        return None

# Load the spaCy model
nlp = load_spacy_model(model_path)


df = pd.read_excel("react.xlsx")
actionlist=[]
for prep in df['Preparation']:
    if 'Get ability' not in prep:
        #print(prep)
        if type(prep) is str:
            actionlist.append(prep.lower())
for id in df['Identification']:
    if type(id) is str:
        actionlist.append(id.lower())
for con in df['Containment']:
    if type(con) is str:
        actionlist.append(con.lower())
for er in df['Eradication']:
    if type(er) is str:
        actionlist.append(er.lower())
for rec in df['Recovery']:
    if type(rec) is str:
        actionlist.append(rec.lower())
"""for les in df['Lessons Learned']:
    if type(les) is str:
        actionlist.append(les)"""
listofpredicates=[]
# Test the trained model
actions=[]
reactid=[]
comments=[]
test_sentences = listactions[2]
for sent in range(len(test_sentences)):
    if test_sentences[sent] in actionlist:
        doc = nlp(test_sentences[sent])
        predicate=[]
        for t in range(len(doc)):
            if t==0 and doc[t].tag_=='VERB':
                predicate.append(str(doc[t]))
            else:
                if doc[t].tag_!='ADP':
                    predicate.append(str(doc[t]))
        #if predicate not in listofpredicates:
        listofpredicates.append(predicate)
        actions.append(test_sentences[sent])
        comments.append(listactions[3][sent])
        reactid.append(listactions[0][sent])
#print(listofpredicates)
print(len(listofpredicates))

def create_sentence(words):
    """Create a sentence from a list of words."""
    # Capitalize the first word
    words[0] = words[0].lower()
    for w in range(len(words)):
        if w==0:
            words[w] = words[w].lower()
        else:
            words[w] = words[w].capitalize()
    
    # Join the words to form a sentence
    sentence = ''.join(words) 

    return sentence

# Example usage
predicates=[]
for word_list in listofpredicates:
    sentence = create_sentence(word_list)
    predicates.append(sentence)
#print(len(predicates))
listdata={'React ID': reactid, 'Label':actions, 'Comment':comments, 'Predicate':predicates}

df_react = pd.DataFrame(listdata)
    
#print(df_react)

csv_file_path = 'counterpredicate.xlsx'

df_react.to_excel(csv_file_path)

# CSV file path
"""csv_file_path = 'counterpredicate.csv'

# Writing list elements to CSV file
# Writing list elements to CSV file
with open(csv_file_path, mode='w', newline='') as file:
    writer = csv.writer(file)
    for item in predicates:
        writer.writerow([item])
file = open("predicates.txt", "r")
contents = file.read()
list_of_contents = contents.split("\n")
file.close()
#print(list_of_contents)"""