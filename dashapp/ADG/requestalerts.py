from elasticsearch import Elasticsearch
import pandas as pd
def alerts():
    # Initialize the Elasticsearch client
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
    #print(response2)

    # Print the last document
    if response1['hits']['hits']:
        last_doc1 = response1['hits']['hits'][0]
        address=last_doc1['_source']['address']
        protocol=last_doc1['_source']['iana_protocol_name']
        port=last_doc1['_source']['port']
        severity=last_doc1['_source']['severity']
        id=last_doc1['_id']
        print(id,address,protocol,port,severity)
    if response2['hits']['hits']:
        last_doc2 = response2['hits']['hits'][0]
        address2=last_doc2['_source']['address']
        protocol2=last_doc2['_source']['iana_protocol_name']
        port2=last_doc2['_source']['port']
        severity2=last_doc2['_source']['severity']
        print(address2,protocol2,port2,severity2)
    else:
        print("No documents found in the index.")

    # Define the path to your CSV file
    excel_file_path = '/var/www/html/ADG/AGpredicates.xlsx'
    #excel_file_path = 'AGpredicates.xlsx'
    # Read the CSV file into a DataFrame
    df = pd.read_excel(excel_file_path)

    # Print the DataFrame
    predicates=df["Predicates"]
    typenode=df["type"]
    numbernodes=df["Nodes"]
    listleaf=[]
    listaction=[]
    if severity=='low' or severity=='None':
        for pred in range(len(predicates)):
            if typenode[pred]=="LEAF":
                param=predicates[pred].split('(')[1].split(')')[0]
                params=param.split(',')
                for p in range(len(params)):
                    val=params[p].split("'")
                    if len(val)>1:
                        params[p]=val[1]
                    else:
                        params[p]=val[0]
                #print(params)
                if address in params and str(port) in params and protocol in params:
                    #print(params)
                    listleaf.append(numbernodes[pred])
    else:
        for pred in range(len(predicates)):
            if typenode[pred]=="OR":
                param=predicates[pred].split('(')[1].split(')')[0]
                params=param.split(',')
                for p in range(len(params)):
                    val=params[p].split("'")
                    if len(val)>1:
                        params[p]=val[1]
                    else:
                        params[p]=val[0]
                #print(params)
                if address in params and str(port) in params and protocol in params:
                    #print(params)
                    listaction.append(numbernodes[pred])
            if typenode[pred]=="LEAF":
                param=predicates[pred].split('(')[1].split(')')[0]
                params=param.split(',')
                for p in range(len(params)):
                    val=params[p].split("'")
                    if len(val)>1:
                        params[p]=val[1]
                    else:
                        params[p]=val[0]
                #print(params)
                if address in params and str(port) in params and protocol in params:
                    #print(params)
                    listleaf.append(numbernodes[pred])

    if len(listaction)!=0 or len(listleaf)!=0:
        print(listaction)
        # Create a DataFrame from the lists
        df = pd.DataFrame({
            'Net': pd.Series(listleaf),
            'Act': pd.Series(listaction)
        })

        # Define the path to save the Excel file
        excel_file_path = '/var/www/html/ADG/alerts.xlsx'

        # Write the DataFrame to an Excel file
        df.to_excel(excel_file_path, index=False)

        print(f'Data successfully written to {excel_file_path}')
    else:
        #print(address2,port2,protocol2)
        if severity2=='low' or severity2=='None':
            for pred in range(len(predicates)):
                print(pred)
                if typenode[pred]=="LEAF":
                    param=predicates[pred].split('(')[1].split(')')[0]
                    params=param.split(',')
                    for p in range(len(params)):
                        val=params[p].split("'")
                        if len(val)>1:
                            params[p]=val[1]
                        else:
                            params[p]=val[0]
                    #print(params, address2, port2, protocol2)
                    #if address2 in params and port2 in params and protocol2 in params:
                    if address2 in params and protocol2 in params and str(port2) in params:
                        #print(params)
                        listleaf.append(numbernodes[pred])
        else:
            for pred in range(len(predicates)):
                if typenode[pred]=="OR":
                    param=predicates[pred].split('(')[1].split(')')[0]
                    params=param.split(',')
                    for p in range(len(params)):
                        val=params[p].split("'")
                        if len(val)>1:
                            params[p]=val[1]
                        else:
                            params[p]=val[0]
                    #print(params, address2, str(port2), protocol2)
                    #if address2 in params and port2 in params and protocol2 in params:
                    if address2 in params and protocol2 in params and str(port2) in params:
                        #print(params, str(port2))
                        listaction.append(numbernodes[pred])
                if typenode[pred]=="LEAF":
                    param=predicates[pred].split('(')[1].split(')')[0]
                    params=param.split(',')
                    for p in range(len(params)):
                        val=params[p].split("'")
                        if len(val)>1:
                            params[p]=val[1]
                        else:
                            params[p]=val[0]
                    #print(params)
                    #if address2 in params and port2 in params and protocol2 in params:
                    if address2 in params and protocol2 in params and str(port2) in params:
                        #print(params)
                        listleaf.append(numbernodes[pred])
    print(listleaf)
    print(listaction)
    #if len(listaction)!=0 or len(listleaf)!=0:
    # Create a DataFrame from the lists
    if len(listaction)!=0 or len(listleaf)!=0:
        df = pd.DataFrame({
            'Net': pd.Series(listleaf),
            'Act': pd.Series(listaction)
        })

        # Define the path to save the Excel file
        excel_file_path = '/var/www/html/ADG/alerts.xlsx'

        # Write the DataFrame to an Excel file
        df.to_excel(excel_file_path, index=False)

        print(f'Data successfully written to {excel_file_path}')