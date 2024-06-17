from elasticsearch import Elasticsearch
from elasticsearch.exceptions import NotFoundError

# Define the Elasticsearch connection parameters
es = Elasticsearch(
    ["http://192.168.1.12:9200/"],  # Your Elasticsearch server URL
    http_auth=('elastic', 'prelude')  # If authentication is required
)

# Define the index, document ID, and the field to update
index_name = 'target'
doc_id = '4io8y48BkDfSyNAVh_uH'
field_to_update = 'port'
new_value = '80'

# Prepare the update query
update_body = {
    'doc': {
        field_to_update: new_value
    }
}

try:
    # Perform the update
    response = es.update(index=index_name, id=doc_id, body=update_body)
    print("Document updated successfully:", response)
except NotFoundError:
    print("Document not found.")
except Exception as e:
    print("Error updating document:", e)
