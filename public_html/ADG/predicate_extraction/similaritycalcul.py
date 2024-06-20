import gensim
import nltk
import itertools
nltk.download('punkt')
# Preprocessing (tokenization and lowercasing)
from nltk.tokenize import word_tokenize
import string
import json
import pandas as pd

model = gensim.models.Word2Vec.load("word2vec.model")  # Load model
countermeasure=[]
mulval=[]
scores=[]
predicatsmul=[]
predicatscount=[]
predcoun=None
# Function to preprocess a sentence
def preprocess_sentence(sentence):
    # Tokenize the sentence into words
    words = word_tokenize(sentence.lower())
    # Remove punctuation
    words = [word for word in words if word not in string.punctuation]
    return words
# Function to compute sentence vector by averaging word vectors
def sentence_vector(sentence):
    words = preprocess_sentence(sentence)
    word_vectors = [model.wv[word] for word in words if word in model.wv]
    if len(word_vectors) == 0:
        return None
    else:
        return sum(word_vectors) / len(word_vectors)

def find_top_similar_sentences(target_sentence, sentence_list, model, top_n=40):
    # Tokenize and preprocess the target sentence
    tokenized_target = preprocess_sentence(target_sentence)
    
    # Calculate similarity scores between the target sentence and each sentence in the list
    similarity_scores = []
    for sentence in sentence_list:
        tokenized_sentence = preprocess_sentence(sentence)
        similarity_score = model.wv.n_similarity(tokenized_target, tokenized_sentence)
        similarity_scores.append((sentence, similarity_score))
    
    # Sort sentences by similarity score (higher score means more similar)
    similarity_scores.sort(key=lambda x: x[1], reverse=True)
    print(similarity_scores)
    # Return the top N most similar sentences
    top_similar_sentences = [score[0] for score in similarity_scores[:top_n]]
    #print(top_similar_sentences)
    return top_similar_sentences


excel_file = "mulvalpred.xlsx"

# Read data from the Excel file
df_mul = pd.read_excel(excel_file)
predicates_list = [name for name in df_mul['Predicates']]
description_list = [name for name in df_mul['Description']]

excel_file1="counterpredicate.xlsx"
df_counter=pd.read_excel(excel_file1)
id_list=[name for name in df_counter['React ID']]
comment_list=[name for name in df_counter['Comment']]
pred_list=[name for name in df_counter['Predicate']]

# Specify the path to your JSON file
json_file_path = 'output.json'

json_data=[]
listoutput=[]
# Open the JSON file and load its contents
with open(json_file_path, 'r') as json_file:
    json_data = json.load(json_file)
#print(json_data)
#print(len(predicates_list))
#print(len(pred_list))
for pred in range(len(predicates_list)):
    #if pred=="vulExists(_machine, _vulID, _program, _range, _consequence)":
    #chercher description de pred dans mulvalpred
    
    for element in json_data:
        if predicates_list[pred] in element:
            desc_mul=description_list[pred]
            #vec1 = sentence_vector(desc_mul)
            #print(desc_mul)
            #max_similarity = -1
            #pred2=None
            prediclist=element[predicates_list[pred]]
            desc_count=[]
            #list_pred_mul=[]
            #print(prediclist)
            for predic in prediclist:
                #print(predic)
                position=pred_list.index(predic.split('(')[0])
                if comment_list[position] not in desc_count:
                    desc_count.append(comment_list[position])
                    #print(predic)
                    #print(comment_list[position])
                
            #print(desc_count)
            # Find the top 5 most similar sentences for the target sentence
            top_similar_sentences = find_top_similar_sentences(desc_mul, desc_count, model, top_n=40)
            json_obj={'Desc':desc_mul,'Top':top_similar_sentences}
            listoutput.append(json_obj)
#print(listoutput)
listmul=[]
listpredmul=[]
listcoun=[]
listpredcoun=[]
listid=[]
for i in range(len(listoutput)):
    #print(listoutput[i]['Desc'])
    positionmul=description_list.index(listoutput[i]['Desc'])
    mult=predicates_list[positionmul]
    #print(positionmul)
    for e in enumerate(listoutput[i]['Top'],1):
        positioncoun=comment_list.index(e[1])
        for o in json_data:
            if predicates_list[positionmul] in o:
                for el in o[predicates_list[positionmul]]:
                    if el.startswith(pred_list[positioncoun]):
                        param=el.split('(')[1].split(')')[0]
        #print(pred_list[positioncoun]+'('+param+')')
        #print(predicates_list[positionmul],e)
        listpredcoun.append(pred_list[positioncoun]+'('+param+')')
        listpredmul.append(predicates_list[positionmul])
        listmul.append(listoutput[i]['Desc'])
        listcoun.append(e[1])
        listid.append(id_list[positioncoun])
# Create a dictionary where keys are column names and values are lists
data = {
    'ID':listid,
    'Countermeasures Predicates': listpredcoun,
    'Attack Predicates': listpredmul,
}

# Create DataFrame from the dictionary
df_table = pd.DataFrame(data)

# Specify the path for the Excel file
excel_file_path = 'predicatesTable.xlsx'

# Export DataFrame to Excel
df_table.to_excel(excel_file_path, index=False)  # Set index=False to exclude row numbers
