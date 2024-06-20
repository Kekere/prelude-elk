import random
from pathlib import Path
import spacy
from spacy.training import Example
import pandas as pd

# Define your custom training data
TRAIN_DATA = [
    ("Practice", {"tags": ["VERB"]}),
    ("Take trainings", {"tags": ["VERB", "NOUN"]}),
    ("Raise personnel awareness", {"tags": ["VERB", "NOUN", "NOUN"]}),
    ("Make personnel report suspicious activity", {"tags": ["VERB", "NOUN", "VERB", "ADJ", "NOUN"]}),
    ("Set up relevant data collection", {"tags": ["VERB", "ADP", "ADJ", "NOUN", "NOUN"]}),
    ("Develop communication map", {"tags": ["VERB", "NOUN", "NOUN"]}),
    ("Make sure there are backups", {"tags": ["VERB", "VERB", "ADP", "VERB", "NOUN"]}),
    ("Get network architecture map", {"tags": ["VERB", "NOUN", "NOUN", "NOUN"]}),
    ("Get access control matrix", {"tags": ["VERB", "NOUN", "NOUN", "NOUN"]}),
    ("Develop assets knowledge base", {"tags" :["VERB", "NOUN", "NOUN", "NOUN"]}),
    ("Check analysis toolset", {"tags" :["VERB", "NOUN", "NOUN"]}),
    ("Access vulnerability management system logs", {"tags" :["VERB", "NOUN", "NOUN", "NOUN", "NOUN"]}),
    ("Connect with trusted communities", {"tags" :["VERB", "ADP", "VERB", "NOUN"]}),
    ("Access external network flow logs", {"tags" :["VERB", "ADJ", "NOUN", "NOUN", "NOUN"]}),
    ("Access internal network flow logs", {"tags" :["VERB", "ADJ", "NOUN", "NOUN", "NOUN"]}),
    ("Access internal HTTP logs", {"tags" :["VERB", "ADJ", "NOUN", "NOUN"]}),
    ("Access external HTTP logs", {"tags" :["VERB", "ADJ", "NOUN", "NOUN"]}),
    ("Access internal DNS logs", {"tags" :["VERB", "ADJ", "NOUN", "NOUN"]}),
    ("Access external DNS logs", {"tags" :["VERB", "ADJ", "NOUN", "NOUN"]}),
    ("Access VPN logs", {"tags" :["VERB", "NOUN", "NOUN"]}),
    ("Access DHCP logs", {"tags" :["VERB", "NOUN", "NOUN"]}),
    ("Access internal packet capture data", {"tags" :["VERB", "ADJ", "NOUN", "NOUN", "NOUN"]}),
    ("Access external packet capture data", {"tags" :["VERB", "ADj", "NOUN", "NOUN", "NOUN"]}),
    ("Get ability to block external IP address", {"tags" :["VERB", "NOUN", "ADP", "VERB", "ADJ", "NOUN", "NOUN"]}),
    ("List victims of security alert", {"tags" :["VERB", "NOUN", "ADP", "NOUN", "NOUN"]}),
    ("List host vulnerabilities", {"tags" :["VERB", "NOUN", "NOUN"]}),
    ("Put compromised accounts on monitoring", {"tags" :["VERB", "VERB", "NOUN", "ADP", "NOUN"]}),
    ("List hosts communicated with internal domain", {"tags" :["VERB", "NOUN", "VERB", "ADP", "ADJ", "NOUN"]}),
    ("List hosts communicated with internal IP", {"tags" :["VERB", "NOUN", "VERB", "ADP", "ADJ", "NOUN"]}),
    ("List hosts communicated with internal URL", {"tags" :["VERB", "NOUN", "VERB", "ADP", "ADJ", "NOUN"]}),
    ("Analyse domain name", {"tags" :["VERB", "NOUN", "NOUN"]}),
    ("Analyse IP", {"tags" :["VERB", "NOUN"]}),
    ("Analyse uri", {"tags" :["VERB", "NOUN"]}),
    ("List hosts communicated by port", {"tags" :["VERB", "NOUN", "VERB", "ADP", "NOUN"]}),
    ("List hosts connected to VPN", {"tags" :["VERB", "NOUN", "VERB", "ADP", "NOUN"]}),
    ("List hosts connected to intranet", {"tags" :["VERB", "NOUN", "VERB", "ADP", "NOUN"]}),
    ("List data transferred", {"tags" :["VERB", "NOUN", "VERB"]}),
    ("Find file by path", {"tags" :["VERB", "NOUN","ADP", "NOUN"]}),
    ("List files deleted", {"tags" :["VERB", "NOUN","VERB"]}),
    ("Patch vulnerability", {"tags" :["VERB", "NOUN"]}),
    ("Block external IP address", {"tags" :["VERB", "ADJ", "NOUN", "NOUN"]}),
    ("Block internal IP address", {"tags" :["VERB", "ADJ", "NOUN", "NOUN"]}),
    ("Block external domain", {"tags" :["VERB", "ADJ", "NOUN"]}),
    ("Block internal domain", {"tags" :["VERB", "ADJ", "NOUN"]}),
    ("Block port external communication", {"tags" :["VERB", "NOUN", "ADJ", "NOUN"]}),
    ("Block port external communication", {"tags" :["VERB", "NOUN", "ADJ","NOUN"]}),
    ("Block sender on email", {"tags": ["VERB","NOUN","ADP", "NOUN"]}),
    ("Block data transferring by content pattern", {"tags" : ["VERB", "NOUN", "VERB", "ADP", "NOUN", "NOUN"]}),
    ("Quarantine file by format", {"tags": ["VERB", "NOUN", "ADP", "NOUN"]}),
    ("Block process by executable hash", {"tags" : ["VERB", "NOUN", "ADP", "ADJ", "NOUN"]}),
    ("Disable system service", {"tags" : ["VERB", "NOUN", "NOUN"]}),
    ("Lock user account", {"tags" : ["VERB", "NOUN", "NOUN"]}),
    ("Report incident to external companies", {"tags" : ["VERB", "NOUN", "ADP", "ADJ", "NOUN"]}),
    ("Remove rogue network device", {"tags" : ["VERB", "ADJ", "NOUN", "NOUN"]}),
    ("Delete email message", {"tags" : ["VERB", "NOUN", "NOUN"]}),
    ("Remove file", {"tags" : ["VERB", "NOUN"]}),
    ("Remove registry key", {"tags" : ["VERB", "NOUN", "NOUN"]}),
    ("Revoke authentication credentials", {"tags" : ["VERB", "NOUN", "NOUN"]}),
    ("Reinstall host from golden image", {"tags" : ["VERB", "NOUN", "ADP", "ADJ", "NOUN"]}),
    ("Unblock blocked IP", {"tags" : ["VERB", "VERB", "NOUN"]}),
    ("Restore data from backup", {"tags" : ["VERB", "NOUN", "ADP", "NOUN"]}),
    ("Restore quarantined email message", {"tags" : ["VERB", "VERB", "NOUN", "NOUN"]}),
    ("Restore quarantined file", {"tags" : ["VERB", "VERB", "NOUN"]}),
    ("Enable disabled service", {"tags" : ["VERB", "VERB", "NOUN"]}),
    ("Unlock locked user account", {"tags" : ["VERB", "VERB", "NOUN", "NOUN"]}),
    ("Develop incident report", {"tags" : ["VERB", "NOUN", "NOUN"]}),
    ("Analyse user-agent", {"tags" : ["VERB", "NOUN", "SYM", "NOUN"]}),
    ("Conduct lessons learned exercise", {"tags" : ["VERB", "NOUN", "VERB", "NOUN"]})
    # Add more training examples as needed
]

# Initialize a blank English model
nlp = spacy.blank("en")

# Create and add the POS tagger component to the pipeline
pos_tagger = nlp.add_pipe("tagger")

# Prepare the training data as Example objects
train_examples = []
for text, annots in TRAIN_DATA:
    example = Example.from_dict(nlp.make_doc(text), annots)
    train_examples.append(example)
    for e in annots['tags']:
        pos_tagger.add_label(e)

# Train the POS tagger
optimizer = nlp.begin_training()
for _ in range(25):  # Adjust number of iterations as needed
    random.shuffle(train_examples)
    for example in train_examples:
        nlp.update([example], sgd=optimizer)

# Save the trained model
output_dir = Path("pos_tagger_model")
output_dir.mkdir(exist_ok=True)
nlp.to_disk(output_dir)

print("Training complete. Model saved to:", output_dir)

