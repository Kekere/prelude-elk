import pandas as pd
import spacy
# Import writer class from csv module
import csv
import json
# Path to your Excel file
excel_file = "predicatmulval.xlsx"

# Read data from the Excel file
df_mul = pd.read_excel(excel_file)
predicates_list = [name for name in df_mul['Predicates']]
description_list = [name for name in df_mul['Description']]
predicates=[]

excel_file1="counterpredicate.xlsx"
df_counter=pd.read_excel(excel_file1)
comment_list=df_counter['Comment']
pred_list=df_counter['Predicate']

with open('predicatmulval.txt') as f:
    line = f.readline()
    while line:
        predicates.append(line.split('\n')[0])
        line = f.readline()
#print(predicates)
def check_prefix_in_list(main_list, prefix_list):
    # Iterate over each element in main_list
    for element in range(len(main_list)):
        # Check if any prefix in prefix_list is a prefix of the current element
        startw=main_list[element].split('(')[0]
        for prefix in range(len(prefix_list)):
            #print(element,prefix)
            if startw in prefix_list[prefix]:
                predicates_list[element] = prefix_list[prefix]
        """if any(element.startswith(prefix) for prefix in prefix_list):
            print(element)
            return True  # Return True as soon as a match is found"""
    return predicates_list  # Return False if no match is found
"""for pred in predicates:
    if 'vulExists' in pred:
        print(pred)"""
result = check_prefix_in_list(predicates_list, predicates)
#print(len(result))
#print(len(description_list))
# Create a DataFrame from the lists

df_mulval = pd.DataFrame({'Predicates': result, 'Description': description_list})
#print(df_mulval)
list_item=[]
for res in result:
    #print(res.split(')')[0].split('(')[0])
    parameters=res.split(')')[0].split('(')[1].split(',')
    arraylist=[]
    #print(res)
    for param in parameters:
        par=param.split('_')[1].capitalize()
        #print(par)
        
        for pred in pred_list:
            if par in pred:
                #predel=None
                #if predel not in arraylist:
                #print(res.split(')')[0].split('(')[0])
                #print(res)
                #print(res,pred)
                if 'Domain' in pred:
                    #predel=pred+'(_domain)'
                    arraylist.append(pred+'(_domain)')
                else:
                    if 'Account' in pred or 'Authentication' in pred or 'User' in pred:
                        arraylist.append(pred+'(_principal)')
                    else:
                        if 'File' in pred or 'Access' in pred:
                            arraylist.append(pred+'(_host, _path)')
                        else:
                            if 'disableSystem' in pred:
                                arraylist.append(pred+'(_host, _program)')
                            else:
                                if 'PortCommunication' in pred or 'PortInternalCommunication' in pred or 'PortExternalCommunication' in pred or 'CommunicatedPort' in pred:
                                    arraylist.append(pred+'(_port)')
                                else:
                                    arraylist.append(pred+'(_host)')

                """if 'Process' in pred or 'IP' in pred:
                    arraylist.append(pred+'(_host)')
                if 'listService' in pred or 'HostVulnerabilities' in pred or 'Victim' in pred:
                    arraylist.append(pred+'(_host)')"""      
            else:  
                if 'Service' in res.split(')')[0].split('(')[0]: 
                    if 'Services' in pred:
                       arraylist.append(pred+'(_host)')   
                    else:
                        if 'SystemService' in pred:
                            arraylist.append(pred+'(_host, program)') 
                else:
                    if res.startswith('execCode') or res.startswith('netAccess') or res.startswith('accessFile'):
                        if 'Process' in pred:
                            arraylist.append(pred+'(_host)')          
                    if 'vul' in res.split(')')[0].split('(')[0]:
                        #print(res)
                        if pred=='patchVulnerability':
                            #print(res.split(')')[0].split('(')[0])
                            #print(pred)
                            if pred+'('+parameters[0]+','+parameters[1]+parameters[2]+')' not in arraylist:
                                #print(pred)
                                #print(parameters)
                                arraylist.append(pred+'('+parameters[0]+','+parameters[1]+parameters[2]+')')

                
                        
    #print(arraylist)
    processed_item={res:arraylist}
    list_item.append(processed_item)
# Specify the file path where you want to save the Excel file
excel_file_path = 'mulvalpred.xlsx'

# Export the DataFrame to Excel
df_mulval.to_excel(excel_file_path, index=False)  # Set index=False to exclude row numbers in the output

#print(list_item)   
# Define the output file path
output_file_path = "output.json"

# Write the list to a JSON file
with open(output_file_path, "w") as json_file:
    json.dump(list_item, json_file, indent=4)

#print(pred_list)