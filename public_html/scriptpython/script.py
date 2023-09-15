# -*- coding: utf-8 -*-
"""
Spyder Editor

This is a temporary script file.
"""
import mysql.connector
import pandas as pd

df = pd.read_excel("matrice.xlsx", header=[0], index_col=[0])

attackerpos='The internet'
exploitation='log4j'
newpos=df.loc[exploitation]
vulexploit='CVE-2021-44228'

if any(isinstance(val, str) for val in newpos)==False:
    for el in range(len(df.loc[attackerpos])):
        if type(df.loc[attackerpos][el]) is str: 
            if df.columns[el]!=exploitation:
                exploitation=df.columns[el]
vullist=[]
conflist=[]
for el in range(len(df.loc[exploitation])):
   #print(df.columns[el])
   if type(df.loc[exploitation][el])==str:
       splitel=df.loc[exploitation][el].split('/')
       vullist.append(splitel[2])
       conflist.append({'prod':df.columns[el],'port':splitel[0],'protocol':splitel[1]})

mydb = mysql.connector.connect(
  host="localhost",
  user="root",
  password="joyful",
  database="iottest"
)

mycursor = mydb.cursor()
listresult=[]
#print(conflist)
config=[]
for cve in range(len(vullist)):


    mycursor.execute("SELECT cveentries.id, cveentries.cveid, cveentry2pbm.pbmid, "
                     "cvepbmtypes.cweid_weakness, cvepbmtypes.cweid_weakness, cwecsqimpact.impact "
    "FROM cveentries, cveentry2pbm, cvepbmtypes, cwecsqimpact, cweconsequences2w, cweweaknesses "
    "WHERE cveentries.cveid = "+"'"+vullist[cve]+"'"+"  AND "
    "cveentry2pbm.entryid = cveentries.id and cvepbmtypes.id=cveentry2pbm.pbmid "
    "and cvepbmtypes.cweid_weakness=cweweaknesses.id "
 "and cweweaknesses.id=cweconsequences2w.wid and cweconsequences2w.impactid=cwecsqimpact.id; ")
    
    myresult = mycursor.fetchall()
    #print(myresult)
    for x in myresult:
      #print(x)
      listresult.append(x)
      config.append(conflist[cve])

#print(len(config), len(listresult))
postcond=[]
for res in range(len(listresult)):   
    mycursor.execute("SELECT cveentries.id, cveentries.cveid, cvepbmtypes.cweid_weakness, cveentry2pbm.pbmid, "
    "cweweaknessesrelations.relatedid "
    "FROM cveentries, cveentry2pbm, cvepbmtypes, cweweaknessesrelations " 
    "WHERE cveentries.cveid = "+"'"+vulexploit+"'"+" AND "
    "cveentry2pbm.entryid = cveentries.id and cvepbmtypes.id=cveentry2pbm.pbmid "
    " and cweweaknessesrelations.nature='CanPrecede' and cweweaknessesrelations.relatedid= "+str(listresult[res][3])+
    " and cweweaknessesrelations.parentid=cvepbmtypes.cweid_weakness ;")
    
    myresult = mycursor.fetchall()
    #print(config[res])
    for x in myresult:
        postcond.append({'cve':x[1],'postcondition':listresult[res][1], 'impact':listresult[res][5], 'config':config[res]})
print(postcond)