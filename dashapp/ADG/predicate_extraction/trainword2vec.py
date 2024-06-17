import nltk
import itertools
nltk.download('punkt')
# Preprocessing (tokenization and lowercasing)
from nltk.tokenize import word_tokenize
import string
import pandas as pd
import gensim
import gensim.downloader as api

# Path to your Excel file
excel_file = "counterpredicate.xlsx"
# Read data from the Excel file
df_counter = pd.read_excel(excel_file)

# Path to your Excel file
excel_file = "predicatmulval.xlsx"
# Read data from the Excel file
df_mulval = pd.read_excel(excel_file)
list1=df_counter['Comment']
list2=df_mulval['Description']

# Combine the sentences from both lists into a single list
combined_list = [x for x in itertools.chain(list1, list2) ]

# Function to preprocess a sentence
def preprocess_sentence(sentence):
    # Tokenize the sentence into words
    words = word_tokenize(sentence.lower())
    # Remove punctuation
    words = [word for word in words if word not in string.punctuation]
    return words

# Preprocess each sentence in the combined list
preprocessed_corpus = [preprocess_sentence(sentence) for sentence in combined_list]

# Train Word2Vec model
model = gensim.models.Word2Vec(preprocessed_corpus, vector_size=200, window=5, workers=4, min_count=1, sg=0)
model.save("word2vec.model")  # Save model