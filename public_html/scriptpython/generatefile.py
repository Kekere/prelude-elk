# -*- coding: utf-8 -*-
"""
Created on Mon Sep 11 14:33:15 2023

@author: khilaire
"""
#import mysql.connector
import pandas as pd

attackerpos=''
attackGoal=''
severity=''
df = pd.read_excel("report.xls")
#print(df.iloc[0]['Package'])
f = open("input.P", "a")
#mydb = mysql.connector.connect(
#  host="localhost",
#  user="root",
#  password="joyful",
#  database="iottest"
#)

#mycursor = mydb.cursor()
#print(df)

if df.iloc[0]['Attack Vector']=='network':
    attackerpos="attackerLocated(internet).\n"

attackGoal="attackGoal(execCode("+df.iloc[0]['Hosts/Images']+" ,_)).\n"
connec="hacl(internet, "+df.iloc[0]['Hosts/Images']+", _, _).\n"
vulexist="vulExists("+df.iloc[0]['Hosts/Images']+", '"+df.iloc[0]["CVE Id"]+"', "+df.iloc[0]['Package'].split(':')[0]+", remoteExploit, privEscalation).\n"
config="networkServiceInfo("+df.iloc[0]['Hosts/Images']+","+df.iloc[0]['Package'].split(':')[0]+", _, _, _)."
#print()
if df.iloc[0]["Severity"]=='medium':
    severity='m'
if df.iloc[0]["Severity"]=='critical':
    severity='c'
if df.iloc[0]["Severity"]=='high':
    severity='h'
if df.iloc[0]["Severity"]=='low':
    severity='l'
    
cvss="cvss('"+df.iloc[0]["CVE Id"]+"',"+severity+").\n"
print(cvss)
f.write(attackerpos)
f.write(attackGoal)
f.write(connec)
f.write(vulexist)
f.write(cvss)
f.write(config)
f.close()

#open and read the file after the appending:
f = open("input.P", "r")
print(f.read())