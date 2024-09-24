from elasticsearch import Elasticsearch
from elasticsearch.exceptions import NotFoundError

# Define the Elasticsearch connection parameters
es = Elasticsearch(
    ["http://172.31.0.4:9200/"],  # Your Elasticsearch server URL
    http_auth=('elastic', 'prelude')  # If authentication is required
)

# Define the index and the search query
index_name1 = 'target'
# Define the index and the search query
index_name2 = 'source'
# Define the search query to get the last document
query1 = {
    'query': {
        'match_all': {}
    },
    'sort': [
        {'@timestamp': {'order': 'desc'}}
    ],
    'size': 1  # Limit the result to 1 document
}

# Perform the search
response1 = es.search(index=index_name1, body=query1)

# Define the search query to get the last document
query2 = {
    'query': {
        'match_all': {}
    },
    'sort': [
        {'@timestamp': {'order': 'desc'}}
    ],
    'size': 1  # Limit the result to 1 document
}

# Perform the search
response2 = es.search(index=index_name2, body=query2)

# Print the last document
if response1['hits']['hits']:
    last_doc1 = response1['hits']['hits'][0]
    address=last_doc1['_source']['address']
    protocol=last_doc1['_source']['iana_protocol_name']
    port=last_doc1['_source']['port']
    severity=last_doc1['_source']['severity']
    id=last_doc1['_id']
    update_body = {
        "doc":{
            "port":"80",
            "iana_protocol_name":"tcp",
            "address":"192.168.32.192",
            "severity":"high"
        }
    }
    es.update(index=index_name1,id=id,body=update_body)
    print(id,address,protocol,port,severity)
if response2['hits']['hits']:
    last_doc2 = response2['hits']['hits'][0]
    address2=last_doc2['_source']['address']
    protocol2=last_doc2['_source']['iana_protocol_name']
    port2=last_doc2['_source']['port']
    severity2=last_doc2['_source']['severity']
    print(address2,protocol2,port2,severity2)
