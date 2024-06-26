import matplotlib.pyplot as plt
import pandas as pd
from sklearn.manifold import TSNE
from pyrdf2vec import RDF2VecTransformer
from pyrdf2vec.embedders import Word2Vec
from pyrdf2vec.graphs import KG
from pyrdf2vec.walkers import RandomWalker
from owlready2 import *
import csv
import rdflib
from pandas.io.parsers import python_parser
from gensim.test.utils import common_texts
from math import sqrt, pow, exp
from numpy import dot
import numpy as np
from numpy.linalg import norm
import gensim
from gensim.matutils import cossim
import rdflib
from gensim.test.utils import common_texts
from rdflib import *
from gensim.models import Phrases
from owlready2 import *
import heapq
import requests
from bs4 import BeautifulSoup
import re
from nltk.tokenize import word_tokenize
import nltk
import numpy as np

def extractcve(cveid):
  print(cveid)
  # Define the NVD vulnerability URL
  nvd_url = "https://nvd.nist.gov/vuln/detail/"+cveid  # Replace with the URL of the specific CVE you want to extract information for
  response = requests.get(nvd_url)
  ontologydata=''
  consequences=[]
  # Check if the request was successful (status code 200)
  if response.status_code == 200:
      # Parse the HTML content of the page
      #soup = BeautifulSoup(response.content,"lxml")
      data = response.text
      # Adding this print will fix the issue for consecutive days.
      #print(data)
      soup = BeautifulSoup(data, "html.parser")
      #print(soup)

      # Extract relevant information from the NVD page
      cve_id = soup.find('span', attrs={'data-testid': 'page-header-vuln-id'}).text.strip()
      description = soup.find('p', {'data-testid': 'vuln-description'}).text.strip()
      published_date = soup.find('span', {'data-testid': 'vuln-published-on'}).text.strip()
      #cvss_score = soup.find('span', {'data-testid': 'vuln-cvssv3-score'}).text.strip()
      if soup.find('td', {'data-testid': 'vuln-CWEs-link-0'})!=None and soup.find('td', {'data-testid':'vuln-CWEs-link-0'}).text.strip()!='NVD-CWE-noinfo':
        cwe=soup.find('td', {'data-testid': 'vuln-CWEs-link-0'}).text.strip()
        urlcwe="https://cwe.mitre.org/data/definitions/"+cwe.split('-')[1]+".html"
        responsecwe = requests.get(urlcwe)
        soupcwe = BeautifulSoup(responsecwe.text, "html.parser")
        if responsecwe.status_code == 200:
          common_consequences_element = soupcwe.find_all('span', {'class': 'subheading'})
          for cons in common_consequences_element:
            consequences.append(cons.nextSibling.text)
      else:
        if soup.find('td', {'data-testid': 'vuln-CWEs-link-1'})!=None:
          cwe=soup.find('td', {'data-testid': 'vuln-CWEs-link-1'}).text.strip()
          urlcwe="https://cwe.mitre.org/data/definitions/"+cwe.split('-')[1]+".html"
          responsecwe = requests.get(urlcwe)
          soupcwe = BeautifulSoup(responsecwe.text, "html.parser")
          if responsecwe.status_code == 200:
            common_consequences_element = soupcwe.find_all('span', {'class': 'subheading'})
            for cons in common_consequences_element:
              consequences.append(cons.nextSibling.text)
        else:
          cwe=""

      #print(cwe)

      cpelist=soup.find_all('pre')
      cpenewlist=[]
      for cpe in cpelist:
        x = re.search("^OR", cpe.text)
        y=re.search("^AND", cpe.text)
        #print(re.search("^cpe",cpe.text))
        if x != None:
          cpenewlist.append(cpe.text.split("*")[1])
        else:
          if y!=None:
            z=cpe.text.split('OR')
            #print(z)
            for e in z:
              a=e.strip().split("*")
              #print(a)
              if len(a)>1:
                for i in a:
                  #print(i.strip())
                  v=re.search("^cpe", i.strip())
                  if v!=None:
                    cpenewlist.append(i.strip())

      
      # Print the extracted information
      #print(f"CVE ID: {cve_id}")
      #print(f"Description: {description}")
      #print(f"Published Date: {published_date}")
      #print(f"Consequences: {consequences}")
      #print(f"CPE: {cpenewlist}")
      local, remote, physical, phishing = "", "", "", ""
      attackposition=""
      remote = description.lower().find("remote")
      phishing = description.lower().find("phishing")
      physical = description.lower().find("physical")
      #print(physical)
      #print(remote)
      local=description.lower().find("local")
      #print(local)
      if local !=-1 or physical!=-1:
        attackposition="local"
      if remote !=-1 or phishing!=-1:
        attackposition="remote"
      #print(attackposition)
      
      codeexecution=np.array(["execute","execution","executing","execute"])
      trustfailure=np.array(["failure","trust","trusted","failed"])
      maninthemiddle=np.array(["man-in-the-middle","mitm"])
      authbypass=np.array(["bypass"])
      tokens=word_tokenize(description.lower())
      impactmethod=''
      #print(tokens)
      i = np.where([codeexecution == i for i in tokens])
      e = np.where([trustfailure == i for i in tokens])
      o = np.where([maninthemiddle == i for i in tokens])
      a = np.where([authbypass == i for i in tokens])
      if len(i[0])!=0:
        impactmethod='Code_Execution'
      if len(e[0])!=0:
        impactmethod='Trust_Failure'
      if len(o[0])!=0:
        impactmethod='Man-in-the-Middle'
      if len(a[0])!=0:
        impactmethod='Authentication_Bypass'
      operating_system=np.array(["rt","gold","debian","server","microsoft","windows","ios","aix","aleris","allegroe","os","android","ubuntu","debian","linux","mac","macos","fedora"])
      software_noun=np.array(["webex","keycloak","openfind","tracker","wordpress","cloud","zimbra","teclib","zebra","soft","unity","word","webex","excel","explorer","office","apache","acrobat","control","modicon","bank","financial","symantec","s-cms","ibm","adobe","realnetworks","trend micro","hp","blue coat","samba","ca","apache","firefox","antivirus","application","smart","app","freeware","sap","mobile","vbscript","digital","client","mcafee","cardio"])
      context=''
      t = np.where([operating_system == i for i in tokens])
      v = np.where([software_noun == i for i in tokens])
      if len(v[0]) !=0:
        context='Application'
      else:
        if 'firmware' in tokens:
          context='firmware'
        if 'hypervisor' in tokens:
          context='hypervisor'
        if 'guest' in tokens:
          ind=tokens.index('guest')
          if t[0]+1==ind or t[0]-1==ind:
            context='Guest_OS'
        else:
          if len(t[0])!=0:
            context='Host_OS'
      logicalimpact=''
      impact1=0
      impact2=0
      impact3=0
      impact4=0
      z=np.where(['dos' in word_tokenize(i.lower()) for i in consequences])
      for i in consequences:
        if 'dos' in word_tokenize(i.lower()):
          impact3=1
        if 'read' in word_tokenize(i.lower()):
          impact1=1
        if 'modify' in word_tokenize(i.lower()):
          impact2=1
        if 'privileges' in word_tokenize(i.lower()):
          impact4=1
        if 'execute' in word_tokenize(i.lower()) and impactmethod=='':
          impactmethod='Code_Execution'
        if 'bypass' in word_tokenize(i.lower()) and impactmethod=='':
          impactmethod='Authentication_Bypass'
      owl_file_path='/var/www/html/ADG/rdfxmlgraph.owl'
      # Read the OWL file
      with open(owl_file_path, 'r') as file:
          contents = file.read()

      # Parse the OWL file using BeautifulSoup
      soupvdo = BeautifulSoup(contents, 'xml')

      # Find the last <rdf:Description> tag
      last_description_tag = soupvdo.find_all('owl:NamedIndividual')[-1]
      #print(last_description_tag)
      cvedata=''
      cvedata='<!-- http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#CVE'+cve_id+ '-->\n<owl:NamedIndividual rdf:about="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#CVE'+cve_id+ '">\n<rdf:type rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Vulnerability"/>\n<untitled-ontology-4:hasIdentity rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#'+cve_id+'"/>\n<untitled-ontology-4:hasOriginatedProduct rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Product'+cve_id+ '"/>\n<untitled-ontology-4:hasScenario rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Sce'+cve_id+'"/>\n</owl:NamedIndividual>'
      dict_attributescve={"rdf:about":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#CVE"+cve_id}
      new_individual_tagscve=soupvdo.new_tag('owl:NamedIndividual', attrs=dict_attributescve)
      new_individual_tagscve.append('\n')
      dict_attributescve2={"rdf:resource":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Vulnerability"}
      new_individual_tagscve.append(soupvdo.new_tag('rdf:type', attrs=dict_attributescve2))
      new_individual_tagscve.append('\n')
      dict_attributescve3={"rdf:resource":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#"+cve_id}
      new_individual_tagscve.append(soupvdo.new_tag("untitled-ontology-4:hasIdentity", attrs=dict_attributescve3))
      new_individual_tagscve.append('\n')
      dict_attributescve4={"rdf:resource":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Product"+cve_id}
      new_individual_tagscve.append(soupvdo.new_tag("untitled-ontology-4:hasOriginatedProduct", attrs=dict_attributescve4))
      new_individual_tagscve.append('\n')
      dict_attributescve5={"rdf:resource":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Sce"+cve_id}
      new_individual_tagscve.append(soupvdo.new_tag("untitled-ontology-4:hasScenario", attrs=dict_attributescve5))
      new_individual_tagscve.append('\n')
      #iddata=''
      #iddata='<owl:NamedIndividual rdf:about="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#'+cve_id+'">\n<rdf:type rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#VulnerabilityIdentifier"/>\n<untitled-ontology-4:value rdf:datatype="http://www.w3.org/2001/XMLSchema#string">'+cve_id+'</untitled-ontology-4:value>\n</owl:NamedIndividual>'
      dict_attributesid={"rdf:about":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#"+cve_id}
      new_individual_tagsid=soupvdo.new_tag("owl:NamedIndividual",attrs=dict_attributesid)
      new_individual_tagsid.append('\n')
      dict_attributesid2={"rdf:resource":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#VulnerabilityIdentifier"}
      new_individual_tagsid.append(soupvdo.new_tag("rdf:type", attrs=dict_attributesid2))
      new_individual_tagsid.append('\n')
      dict_attributesid3={"rdf:datatype":"http://www.w3.org/2001/XMLSchema#string"}
      nouveau=soupvdo.new_tag("untitled-ontology-4:value", attrs=dict_attributesid3)
      nouveau.string=cve_id
      new_individual_tagsid.append(nouveau)
      new_individual_tagsid.append('\n')
      attackerdata=''
      attackerdata=' <!-- http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Sce'+cve_id+ '-->\n<owl:NamedIndividual rdf:about="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Sce'+cve_id+'">\n<rdf:type rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Scenario"/>\n<untitled-ontology-4:affectsProduct rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Product'+cve_id+'"/>\n<untitled-ontology-4:hasAction rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Action'+cve_id+'"/>\n<untitled-ontology-4:hasExploitedWeakness rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#'+cwe+'"/>\n<untitled-ontology-4:requiresAttackTheater rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Remote"/>\n</owl:NamedIndividual>'
      dict_attributesact={"rdf:about":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Sce"+cve_id}
      new_individual_tagsact=soupvdo.new_tag('owl:NamedIndividual', attrs=dict_attributesact)
      new_individual_tagsact.append('\n')
      dict_attributesact2={"rdf:resource":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Scenario"}
      new_individual_tagsact.append(soupvdo.new_tag('rdf:type', attrs=dict_attributesact2))
      new_individual_tagsact.append('\n')
      dict_attributesact3={"rdf:resource":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Product"+cve_id}
      new_individual_tagsact.append(soupvdo.new_tag("untitled-ontology-4:affectsProduct", attrs=dict_attributesact3))
      new_individual_tagsact.append('\n')
      dict_attributesact4={"rdf:resource":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Action"+cve_id}
      new_individual_tagsact.append(soupvdo.new_tag("untitled-ontology-4:hasAction", attrs=dict_attributesact4))
      new_individual_tagsact.append('\n')
      if cwe!="":
        dict_attributesact5={"rdf:resource":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#"+cwe}
        new_individual_tagsact.append(soupvdo.new_tag("untitled-ontology-4:hasExploitedWeakness", attrs=dict_attributesact5))
        new_individual_tagsact.append('\n')
      dict_attributesact6={"rdf:resource":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#"+attackposition}
      new_individual_tagsact.append(soupvdo.new_tag("untitled-ontology-4:requiresAttackTheater", attrs=dict_attributesact6))
      new_individual_tagsact.append('\n')
      last_description_tag.insert_after("\n")
      last_description_tag.insert_after(new_individual_tagscve)
      last_description_tag.insert_after(new_individual_tagsid)
      last_description_tag.insert_after(new_individual_tagsact)
      #actiondata=''
      if impact1==0 and impact2==0 and impact3==0 and impact4==0 and impactmethod!='':
        dict_attributesmet={"rdf:about":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Action"+cve_id}
        new_individual_tagsmet=soupvdo.new_tag("owl:NamedIndividual",attrs=dict_attributesmet)
        new_individual_tagsmet.append('\n')
        dict_attributesmet1={"rdf:resource":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Action"}
        new_individual_tagsmet.append(soupvdo.new_tag('rdf:type', attrs=dict_attributesmet1))
        new_individual_tagsmet.append('\n')
        dict_attributesmet2={"rdf:resource":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#"+impactmethod}
        new_individual_tagsmet.append(soupvdo.new_tag("untitled-ontology-4:hasImpactMethod",attrs=dict_attributesmet2))
        new_individual_tagsmet.append('\n')
        dict_attributesmet3={"rdf:resource":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#"+context}
        new_individual_tagsmet.append(soupvdo.new_tag("untitled-ontology-4:affectsContext", attrs=dict_attributesmet3))
        new_individual_tagsmet.append('\n')
        last_description_tag.insert_after(new_individual_tagsmet)
        #actiondata='<!-- http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Action'+cve_id+ '-->\n<owl:NamedIndividual rdf:about="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Action'+cve_id+ '">\n<rdf:type rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Action"/>\n<untitled-ontology-4:affectsContext rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#'+context+'"/>\n<untitled-ontology-4:hasImpactMethod rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#'+impactmethod+'"/>\n</owl:NamedIndividual>'
      if impact1==1 and impact2==0 and impact3==0 and impact4==0:
        dict_attributesmet={"rdf:about":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Action"+cve_id}
        new_individual_tagsmet=soupvdo.new_tag("owl:NamedIndividual",attrs=dict_attributesmet)
        new_individual_tagsmet.append('\n')
        dict_attributesmet1={"rdf:resource":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Action"}
        new_individual_tagsmet.append(soupvdo.new_tag('rdf:type', attrs=dict_attributesmet1))
        new_individual_tagsmet.append('\n')
        dict_attributesmet2={"rdf:resource":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#"+impactmethod}
        new_individual_tagsmet.append(soupvdo.new_tag("untitled-ontology-4:hasImpactMethod",attrs=dict_attributesmet2))
        new_individual_tagsmet.append('\n')
        dict_attributesmet3={"rdf:resource":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#"+context}
        new_individual_tagsmet.append(soupvdo.new_tag("untitled-ontology-4:affectsContext", attrs=dict_attributesmet3))
        new_individual_tagsmet.append('\n')
        dict_attributemet4={"rdf:resource":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Impact1"}
        new_individual_tagsmet.append(soupvdo.new_tag("untitled-ontology-4:resultsInImpact",attrs=dict_attributemet4))
        new_individual_tagsmet.append('\n')
        last_description_tag.insert_after(new_individual_tagsmet)
        #actiondata='<!-- http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Action'+cve_id+ '-->\n<owl:NamedIndividual rdf:about="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Action'+cve_id+ '">\n<rdf:type rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Action"/>\n<untitled-ontology-4:affectsContext rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#'+context+'"/>\n<untitled-ontology-4:hasImpactMethod rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#'+impactmethod+'"/>\n<untitled-ontology-4:resultsInImpact rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Impact1"/>\n</owl:NamedIndividual>'
      if impact1==1 and impact2==1 and impact3==0 and impact4==0:
        dict_attributesmet={"rdf:about":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Action"+cve_id}
        new_individual_tagsmet=soupvdo.new_tag("owl:NamedIndividual",attrs=dict_attributesmet)
        new_individual_tagsmet.append('\n')
        dict_attributesmet2={"rdf:resource":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#"+impactmethod}
        new_individual_tagsmet.append(soupvdo.new_tag("untitled-ontology-4:hasImpactMethod",attrs=dict_attributesmet2))
        new_individual_tagsmet.append('\n')
        dict_attributesmet3={"rdf:resource":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#"+context}
        new_individual_tagsmet.append(soupvdo.new_tag("untitled-ontology-4:affectsContext", attrs=dict_attributesmet3))
        new_individual_tagsmet.append('\n')
        dict_attributemet4={"rdf:resource":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Impact1"}
        new_individual_tagsmet.append(soupvdo.new_tag("untitled-ontology-4:resultsInImpact",attrs=dict_attributemet4))
        new_individual_tagsmet.append('\n')
        dict_attributemet5={"rdf:resource":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Impact2"}
        new_individual_tagsmet.append(soupvdo.new_tag("untitled-ontology-4:resultsInImpact",attrs=dict_attributemet5))
        new_individual_tagsmet.append('\n')
        last_description_tag.insert_after(new_individual_tagsmet)
        #actiondata='<!-- http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Action'+cve_id+ '-->\n<owl:NamedIndividual rdf:about="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Action'+cve_id+ '">\n<rdf:type rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Action"/>\n<untitled-ontology-4:affectsContext rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#'+context+'"/>\n<untitled-ontology-4:hasImpactMethod rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#'+impactmethod+'"/>\n<untitled-ontology-4:resultsInImpact rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Impact1"/>\n<untitled-ontology-4:resultsInImpact rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Impact2"/>\n</owl:NamedIndividual>'
      if impact1==1 and impact2==0 and impact3==1 and impact4==0:
        dict_attributesmet={"rdf:about":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Action"+cve_id}
        new_individual_tagsmet=soupvdo.new_tag("owl:NamedIndividual",attrs=dict_attributesmet)
        new_individual_tagsmet.append('\n')
        dict_attributesmet1={"rdf:resource":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Action"}
        new_individual_tagsmet.append(soupvdo.new_tag('rdf:type', attrs=dict_attributesmet1))
        new_individual_tagsmet.append('\n')
        dict_attributesmet2={"rdf:resource":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#"+impactmethod}
        new_individual_tagsmet.append(soupvdo.new_tag("untitled-ontology-4:hasImpactMethod",attrs=dict_attributesmet2))
        new_individual_tagsmet.append('\n')
        dict_attributesmet3={"rdf:resource":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#"+context}
        new_individual_tagsmet.append(soupvdo.new_tag("untitled-ontology-4:affectsContext", attrs=dict_attributesmet3))
        new_individual_tagsmet.append('\n')
        dict_attributemet4={"rdf:resource":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Impact1"}
        new_individual_tagsmet.append(soupvdo.new_tag("untitled-ontology-4:resultsInImpact",attrs=dict_attributemet4))
        new_individual_tagsmet.append('\n')
        dict_attributemet5={"rdf:resource":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Impact3"}
        new_individual_tagsmet.append(soupvdo.new_tag("untitled-ontology-4:resultsInImpact",attrs=dict_attributemet5))
        new_individual_tagsmet.append('\n')
        last_description_tag.insert_after(new_individual_tagsmet)
        #actiondata='<!-- http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Action'+cve_id+ '-->\n<owl:NamedIndividual rdf:about="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Action'+cve_id+ '">\n<rdf:type rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Action"/>\n<untitled-ontology-4:affectsContext rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#'+context+'"/>\n<untitled-ontology-4:hasImpactMethod rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#'+impactmethod+'"/>\n<untitled-ontology-4:resultsInImpact rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Impact1"/>\n<untitled-ontology-4:resultsInImpact rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Impact3"/>\n</owl:NamedIndividual>'
      if impact1==0 and impact2==1 and impact3==0  and impact4==0:
        dict_attributesmet={"rdf:about":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Action"+cve_id}
        new_individual_tagsmet=soupvdo.new_tag("owl:NamedIndividual",attrs=dict_attributesmet)
        new_individual_tagsmet.append('\n')
        dict_attributesmet1={"rdf:resource":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Action"}
        new_individual_tagsmet.append(soupvdo.new_tag('rdf:type', attrs=dict_attributesmet1))
        new_individual_tagsmet.append('\n')
        dict_attributesmet2={"rdf:resource":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#"+impactmethod}
        new_individual_tagsmet.append(soupvdo.new_tag("untitled-ontology-4:hasImpactMethod",attrs=dict_attributesmet2))
        new_individual_tagsmet.append('\n')
        dict_attributesmet3={"rdf:resource":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#"+context}
        new_individual_tagsmet.append(soupvdo.new_tag("untitled-ontology-4:affectsContext", attrs=dict_attributesmet3))
        new_individual_tagsmet.append('\n')
        dict_attributemet4={"rdf:resource":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Impact2"}
        new_individual_tagsmet.append(soupvdo.new_tag("untitled-ontology-4:resultsInImpact",attrs=dict_attributemet4))
        new_individual_tagsmet.append('\n')
        last_description_tag.insert_after(new_individual_tagsmet)
        #actiondata='<!-- http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Action'+cve_id+ '-->\n<owl:NamedIndividual rdf:about="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Action'+cve_id+ '">\n<rdf:type rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Action"/>\n<untitled-ontology-4:affectsContext rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#'+context+'"/>\n<untitled-ontology-4:hasImpactMethod rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#'+impactmethod+'"/>\n<untitled-ontology-4:resultsInImpact rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Impact2"/>\n</owl:NamedIndividual>'
        #actiondata='<!-- http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Action'+cve_id+ '-->\n<owl:NamedIndividual rdf:about="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Action'+cve_id+ '">\n<rdf:type rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Action"/>\n<untitled-ontology-4:affectsContext rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#'+context+'"/>\n<untitled-ontology-4:hasImpactMethod rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#'+impactmethod+'"/>\n<untitled-ontology-4:resultsInImpact rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Impact1"/>\n<untitled-ontology-4:resultsInImpact rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Impact2"/>\n</owl:NamedIndividual>'
      if impact1==1 and impact2==0 and impact3==0 and impact4==1:
        dict_attributesmet={"rdf:about":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Action"+cve_id}
        new_individual_tagsmet=soupvdo.new_tag("owl:NamedIndividual",attrs=dict_attributesmet)
        new_individual_tagsmet.append('\n')
        dict_attributesmet1={"rdf:resource":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Action"}
        new_individual_tagsmet.append(soupvdo.new_tag('rdf:type', attrs=dict_attributesmet1))
        new_individual_tagsmet.append('\n')
        dict_attributesmet2={"rdf:resource":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#"+impactmethod}
        new_individual_tagsmet.append(soupvdo.new_tag("untitled-ontology-4:hasImpactMethod",attrs=dict_attributesmet2))
        new_individual_tagsmet.append('\n')
        dict_attributesmet3={"rdf:resource":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#"+context}
        new_individual_tagsmet.append(soupvdo.new_tag("untitled-ontology-4:affectsContext", attrs=dict_attributesmet3))
        new_individual_tagsmet.append('\n')
        dict_attributemet4={"rdf:resource":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Impact1"}
        new_individual_tagsmet.append(soupvdo.new_tag("untitled-ontology-4:resultsInImpact",attrs=dict_attributemet4))
        new_individual_tagsmet.append('\n')
        dict_attributemet5={"rdf:resource":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Impact4"}
        new_individual_tagsmet.append(soupvdo.new_tag("untitled-ontology-4:resultsInImpact",attrs=dict_attributemet5))
        new_individual_tagsmet.append('\n')
        last_description_tag.insert_after(new_individual_tagsmet)
        #actiondata='<!-- http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Action'+cve_id+ '-->\n<owl:NamedIndividual rdf:about="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Action'+cve_id+ '">\n<rdf:type rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Action"/>\n<untitled-ontology-4:affectsContext rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#'+context+'"/>\n<untitled-ontology-4:hasImpactMethod rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#'+impactmethod+'"/>\n<untitled-ontology-4:resultsInImpact rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Impact1"/>\n<untitled-ontology-4:resultsInImpact rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Impact4"/>\n</owl:NamedIndividual>'
      if impact1==0 and impact2==0 and impact3==1 and impact4==0:
        dict_attributesmet={"rdf:about":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Action"+cve_id}
        new_individual_tagsmet=soupvdo.new_tag("owl:NamedIndividual",attrs=dict_attributesmet)
        new_individual_tagsmet.append('\n')
        dict_attributesmet1={"rdf:resource":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Action"}
        new_individual_tagsmet.append(soupvdo.new_tag('rdf:type', attrs=dict_attributesmet1))
        new_individual_tagsmet.append('\n')
        dict_attributesmet2={"rdf:resource":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#"+impactmethod}
        new_individual_tagsmet.append(soupvdo.new_tag("untitled-ontology-4:hasImpactMethod",attrs=dict_attributesmet2))
        new_individual_tagsmet.append('\n')
        dict_attributesmet3={"rdf:resource":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#"+context}
        new_individual_tagsmet.append(soupvdo.new_tag("untitled-ontology-4:affectsContext", attrs=dict_attributesmet3))
        new_individual_tagsmet.append('\n')
        dict_attributemet4={"rdf:resource":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Impact3"}
        new_individual_tagsmet.append(soupvdo.new_tag("untitled-ontology-4:resultsInImpact",attrs=dict_attributemet4))
        new_individual_tagsmet.append('\n')
        last_description_tag.insert_after(new_individual_tagsmet)
        #actiondata='<!-- http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Action'+cve_id+ '-->\n<owl:NamedIndividual rdf:about="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Action'+cve_id+ '">\n<rdf:type rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Action"/>\n<untitled-ontology-4:affectsContext rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#'+context+'"/>\n<untitled-ontology-4:hasImpactMethod rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#'+impactmethod+'"/>\n<untitled-ontology-4:resultsInImpact rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Impact3"/>\n</owl:NamedIndividual>'
        #actiondata='<!-- http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Action'+cve_id+ '-->\n<owl:NamedIndividual rdf:about="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Action'+cve_id+ '">\n<rdf:type rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Action"/>\n<untitled-ontology-4:affectsContext rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#'+context+'"/>\n<untitled-ontology-4:hasImpactMethod rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#'+impactmethod+'"/>\n<untitled-ontology-4:resultsInImpact rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Impact1"/>\n<untitled-ontology-4:resultsInImpact rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Impact2"/>\n</owl:NamedIndividual>'
      if impact1==0 and impact2==1 and impact3==1 and impact4==0:
        dict_attributesmet={"rdf:about":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Action"+cve_id}
        new_individual_tagsmet=soupvdo.new_tag("owl:NamedIndividual",attrs=dict_attributesmet)
        new_individual_tagsmet.append('\n')
        dict_attributesmet1={"rdf:resource":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Action"}
        new_individual_tagsmet.append(soupvdo.new_tag('rdf:type', attrs=dict_attributesmet1))
        new_individual_tagsmet.append('\n')
        dict_attributesmet2={"rdf:resource":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#"+impactmethod}
        new_individual_tagsmet.append(soupvdo.new_tag("untitled-ontology-4:hasImpactMethod",attrs=dict_attributesmet2))
        new_individual_tagsmet.append('\n')
        dict_attributesmet3={"rdf:resource":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#"+context}
        new_individual_tagsmet.append(soupvdo.new_tag("untitled-ontology-4:affectsContext", attrs=dict_attributesmet3))
        new_individual_tagsmet.append('\n')
        dict_attributemet4={"rdf:resource":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Impact2"}
        new_individual_tagsmet.append(soupvdo.new_tag("untitled-ontology-4:resultsInImpact",attrs=dict_attributemet4))
        new_individual_tagsmet.append('\n')
        dict_attributemet5={"rdf:resource":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Impact3"}
        new_individual_tagsmet.append(soupvdo.new_tag("untitled-ontology-4:resultsInImpact",attrs=dict_attributemet5))
        new_individual_tagsmet.append('\n')
        last_description_tag.insert_after(new_individual_tagsmet)
        #actiondata='<!-- http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Action'+cve_id+ '-->\n<owl:NamedIndividual rdf:about="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Action'+cve_id+ '">\n<rdf:type rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Action"/>\n<untitled-ontology-4:affectsContext rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#'+context+'"/>\n<untitled-ontology-4:hasImpactMethod rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#'+impactmethod+'"/>\n<untitled-ontology-4:resultsInImpact rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Impact2"/>\n<untitled-ontology-4:resultsInImpact rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Impact3"/>\n</owl:NamedIndividual>'
      if impact1==0 and impact2==1 and impact3==0 and impact4==1:
        dict_attributesmet={"rdf:about":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Action"+cve_id}
        new_individual_tagsmet=soupvdo.new_tag("owl:NamedIndividual",attrs=dict_attributesmet)
        new_individual_tagsmet.append('\n')
        dict_attributesmet1={"rdf:resource":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Action"}
        new_individual_tagsmet.append(soupvdo.new_tag('rdf:type', attrs=dict_attributesmet1))
        new_individual_tagsmet.append('\n')
        dict_attributesmet2={"rdf:resource":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#"+impactmethod}
        new_individual_tagsmet.append(soupvdo.new_tag("untitled-ontology-4:hasImpactMethod",attrs=dict_attributesmet2))
        new_individual_tagsmet.append('\n')
        dict_attributesmet3={"rdf:resource":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#"+context}
        new_individual_tagsmet.append(soupvdo.new_tag("untitled-ontology-4:affectsContext", attrs=dict_attributesmet3))
        new_individual_tagsmet.append('\n')
        dict_attributemet4={"rdf:resource":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Impact4"}
        new_individual_tagsmet.append(soupvdo.new_tag("untitled-ontology-4:resultsInImpact",attrs=dict_attributemet4))
        new_individual_tagsmet.append('\n')
        dict_attributemet5={"rdf:resource":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Impact2"}
        new_individual_tagsmet.append(soupvdo.new_tag("untitled-ontology-4:resultsInImpact",attrs=dict_attributemet5))
        new_individual_tagsmet.append('\n')
        last_description_tag.insert_after(new_individual_tagsmet)
        #actiondata='<!-- http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Action'+cve_id+ '-->\n<owl:NamedIndividual rdf:about="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Action'+cve_id+ '">\n<rdf:type rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Action"/>\n<untitled-ontology-4:affectsContext rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#'+context+'"/>\n<untitled-ontology-4:hasImpactMethod rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#'+impactmethod+'"/>\n<untitled-ontology-4:resultsInImpact rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Impact2"/>\n<untitled-ontology-4:resultsInImpact rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Impact4"/>\n</owl:NamedIndividual>'
      if impact1==1 and impact2==1 and impact3==1 and impact4==0:
        dict_attributesmet={"rdf:about":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Action"+cve_id}
        new_individual_tagsmet=soupvdo.new_tag("owl:NamedIndividual",attrs=dict_attributesmet)
        new_individual_tagsmet.append('\n')
        dict_attributesmet1={"rdf:resource":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Action"}
        new_individual_tagsmet.append(soupvdo.new_tag('rdf:type', attrs=dict_attributesmet1))
        new_individual_tagsmet.append('\n')
        dict_attributesmet2={"rdf:resource":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#"+impactmethod}
        new_individual_tagsmet.append(soupvdo.new_tag("untitled-ontology-4:hasImpactMethod",attrs=dict_attributesmet2))
        new_individual_tagsmet.append('\n')
        dict_attributesmet3={"rdf:resource":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#"+context}
        new_individual_tagsmet.append(soupvdo.new_tag("untitled-ontology-4:affectsContext", attrs=dict_attributesmet3))
        new_individual_tagsmet.append('\n')
        dict_attributemet4={"rdf:resource":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Impact1"}
        new_individual_tagsmet.append(soupvdo.new_tag("untitled-ontology-4:resultsInImpact",attrs=dict_attributemet4))
        new_individual_tagsmet.append('\n')
        dict_attributemet5={"rdf:resource":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Impact2"}
        new_individual_tagsmet.append(soupvdo.new_tag("untitled-ontology-4:resultsInImpact",attrs=dict_attributemet5))
        new_individual_tagsmet.append('\n')
        dict_attributemet6={"rdf:resource":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Impact3"}
        new_individual_tagsmet.append(soupvdo.new_tag("untitled-ontology-4:resultsInImpact",attrs=dict_attributemet6))
        new_individual_tagsmet.append('\n')
        last_description_tag.insert_after(new_individual_tagsmet)
        #actiondata='<!-- http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Action'+cve_id+ '-->\n<owl:NamedIndividual rdf:about="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Action'+cve_id+ '">\n<rdf:type rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Action"/>\n<untitled-ontology-4:affectsContext rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#'+context+'"/>\n<untitled-ontology-4:hasImpactMethod rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#'+impactmethod+'"/>\n<untitled-ontology-4:resultsInImpact rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Impact1"/>\n<untitled-ontology-4:resultsInImpact rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Impact2"/>\n<untitled-ontology-4:resultsInImpact rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Impact3"/>\n</owl:NamedIndividual>'
      if impact1==0 and impact2==0 and impact3==0 and impact4==1:
        dict_attributesmet={"rdf:about":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Action"+cve_id}
        new_individual_tagsmet=soupvdo.new_tag("owl:NamedIndividual",attrs=dict_attributesmet)
        new_individual_tagsmet.append('\n')
        dict_attributesmet1={"rdf:resource":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Action"}
        new_individual_tagsmet.append(soupvdo.new_tag('rdf:type', attrs=dict_attributesmet1))
        new_individual_tagsmet.append('\n')
        dict_attributesmet2={"rdf:resource":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#"+impactmethod}
        new_individual_tagsmet.append(soupvdo.new_tag("untitled-ontology-4:hasImpactMethod",attrs=dict_attributesmet2))
        new_individual_tagsmet.append('\n')
        dict_attributesmet3={"rdf:resource":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#"+context}
        new_individual_tagsmet.append(soupvdo.new_tag("untitled-ontology-4:affectsContext", attrs=dict_attributesmet3))
        new_individual_tagsmet.append('\n')
        dict_attributemet4={"rdf:resource":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Impact4"}
        new_individual_tagsmet.append(soupvdo.new_tag("untitled-ontology-4:resultsInImpact",attrs=dict_attributemet4))
        new_individual_tagsmet.append('\n')
        last_description_tag.insert_after(new_individual_tagsmet)
        #actiondata='<!-- http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Action'+cve_id+ '-->\n<owl:NamedIndividual rdf:about="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Action'+cve_id+ '">\n<rdf:type rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Action"/>\n<untitled-ontology-4:affectsContext rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#'+context+'"/>\n<untitled-ontology-4:hasImpactMethod rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#'+impactmethod+'"/>\n<untitled-ontology-4:resultsInImpact rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Impact4"/>\n</owl:NamedIndividual>'
      if impact1==0 and impact2==0 and impact3==1 and impact4==1:
        dict_attributesmet={"rdf:about":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Action"+cve_id}
        new_individual_tagsmet=soupvdo.new_tag("owl:NamedIndividual",attrs=dict_attributesmet)
        new_individual_tagsmet.append('\n')
        dict_attributesmet1={"rdf:resource":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Action"}
        new_individual_tagsmet.append(soupvdo.new_tag('rdf:type', attrs=dict_attributesmet1))
        new_individual_tagsmet.append('\n')
        dict_attributesmet2={"rdf:resource":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#"+impactmethod}
        new_individual_tagsmet.append(soupvdo.new_tag("untitled-ontology-4:hasImpactMethod",attrs=dict_attributesmet2))
        new_individual_tagsmet.append('\n')
        dict_attributesmet3={"rdf:resource":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#"+context}
        new_individual_tagsmet.append(soupvdo.new_tag("untitled-ontology-4:affectsContext", attrs=dict_attributesmet3))
        new_individual_tagsmet.append('\n')
        dict_attributemet4={"rdf:resource":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Impact3"}
        new_individual_tagsmet.append(soupvdo.new_tag("untitled-ontology-4:resultsInImpact",attrs=dict_attributemet4))
        new_individual_tagsmet.append('\n')
        dict_attributemet5={"rdf:resource":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Impact4"}
        new_individual_tagsmet.append(soupvdo.new_tag("untitled-ontology-4:resultsInImpact",attrs=dict_attributemet5))
        new_individual_tagsmet.append('\n')
        last_description_tag.insert_after(new_individual_tagsmet)
        #actiondata='<!-- http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Action'+cve_id+ '-->\n<owl:NamedIndividual rdf:about="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Action'+cve_id+ '">\n<rdf:type rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Action"/>\n<untitled-ontology-4:affectsContext rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#'+context+'"/>\n<untitled-ontology-4:hasImpactMethod rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#'+impactmethod+'"/>\n\n<untitled-ontology-4:resultsInImpact rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Impact3"/>\n<untitled-ontology-4:resultsInImpact rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Impact4"/>\n</owl:NamedIndividual>'
      if impact1==0 and impact2==1 and impact3==1 and impact4==1:
        dict_attributesmet={"rdf:about":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Action"+cve_id}
        new_individual_tagsmet=soupvdo.new_tag("owl:NamedIndividual",attrs=dict_attributesmet)
        new_individual_tagsmet.append('\n')
        dict_attributesmet1={"rdf:resource":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Action"}
        new_individual_tagsmet.append(soupvdo.new_tag('rdf:type', attrs=dict_attributesmet1))
        new_individual_tagsmet.append('\n')
        dict_attributesmet2={"rdf:resource":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#"+impactmethod}
        new_individual_tagsmet.append(soupvdo.new_tag("untitled-ontology-4:hasImpactMethod",attrs=dict_attributesmet2))
        new_individual_tagsmet.append('\n')
        dict_attributesmet3={"rdf:resource":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#"+context}
        new_individual_tagsmet.append(soupvdo.new_tag("untitled-ontology-4:affectsContext", attrs=dict_attributesmet3))
        new_individual_tagsmet.append('\n')
        dict_attributemet4={"rdf:resource":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Impact2"}
        new_individual_tagsmet.append(soupvdo.new_tag("untitled-ontology-4:resultsInImpact",attrs=dict_attributemet4))
        new_individual_tagsmet.append('\n')
        dict_attributemet5={"rdf:resource":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Impact3"}
        new_individual_tagsmet.append(soupvdo.new_tag("untitled-ontology-4:resultsInImpact",attrs=dict_attributemet5))
        new_individual_tagsmet.append('\n')
        dict_attributemet6={"rdf:resource":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#4"}
        new_individual_tagsmet.append(soupvdo.new_tag("untitled-ontology-4:resultsInImpact",attrs=dict_attributemet6))
        new_individual_tagsmet.append('\n')
        last_description_tag.insert_after(new_individual_tagsmet)
        #actiondata='<!-- http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Action'+cve_id+ '-->\n<owl:NamedIndividual rdf:about="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Action'+cve_id+ '">\n<rdf:type rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Action"/>\n<untitled-ontology-4:affectsContext rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#'+context+'"/>\n<untitled-ontology-4:hasImpactMethod rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#'+impactmethod+'"/>\n<untitled-ontology-4:resultsInImpact rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Impact2"/>\n<untitled-ontology-4:resultsInImpact rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Impact3"/>\n<untitled-ontology-4:resultsInImpact rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Impact4"/>\n</owl:NamedIndividual>'
      if impact1==1 and impact2==1 and impact3==1 and impact4==1:
        dict_attributesmet={"rdf:about":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Action"+cve_id}
        new_individual_tagsmet=soupvdo.new_tag("owl:NamedIndividual",attrs=dict_attributesmet)
        new_individual_tagsmet.append('\n')
        dict_attributesmet1={"rdf:resource":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Action"}
        new_individual_tagsmet.append(soupvdo.new_tag('rdf:type', attrs=dict_attributesmet1))
        new_individual_tagsmet.append('\n')
        dict_attributesmet2={"rdf:resource":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#"+impactmethod}
        new_individual_tagsmet.append(soupvdo.new_tag("untitled-ontology-4:hasImpactMethod",attrs=dict_attributesmet2))
        new_individual_tagsmet.append('\n')
        dict_attributesmet3={"rdf:resource":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#"+context}
        new_individual_tagsmet.append(soupvdo.new_tag("untitled-ontology-4:affectsContext", attrs=dict_attributesmet3))
        new_individual_tagsmet.append('\n')
        dict_attributemet4={"rdf:resource":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Impact1"}
        new_individual_tagsmet.append(soupvdo.new_tag("untitled-ontology-4:resultsInImpact",attrs=dict_attributemet4))
        new_individual_tagsmet.append('\n')
        dict_attributemet5={"rdf:resource":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Impact2"}
        new_individual_tagsmet.append(soupvdo.new_tag("untitled-ontology-4:resultsInImpact",attrs=dict_attributemet5))
        new_individual_tagsmet.append('\n')
        dict_attributemet6={"rdf:resource":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Impact3"}
        new_individual_tagsmet.append(soupvdo.new_tag("untitled-ontology-4:resultsInImpact",attrs=dict_attributemet6))
        new_individual_tagsmet.append('\n')
        dict_attributemet7={"rdf:resource":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Impact4"}
        new_individual_tagsmet.append(soupvdo.new_tag("untitled-ontology-4:resultsInImpact",attrs=dict_attributemet7))
        new_individual_tagsmet.append('\n')
        last_description_tag.insert_after(new_individual_tagsmet)
        #actiondata='<!-- http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Action'+cve_id+ '-->\n<owl:NamedIndividual rdf:about="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Action'+cve_id+ '">\n<rdf:type rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Action"/>\n<untitled-ontology-4:affectsContext rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#'+context+'"/>\n<untitled-ontology-4:hasImpactMethod rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#'+impactmethod+'"/>\n<untitled-ontology-4:resultsInImpact rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Impact1"/>\n<untitled-ontology-4:resultsInImpact rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Impact2"/>\n<untitled-ontology-4:resultsInImpact rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Impact3"/>\n<untitled-ontology-4:resultsInImpact rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Impact4"/>\n</owl:NamedIndividual>'
        
      #productenumdata=''
      #new_individual_tags=soupvdo.new_tag()

      

      dict_attributes={"rdf:about":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Product"+cve_id}
      new_individual_tags = soupvdo.new_tag('owl:NamedIndividual', attrs=dict_attributes)
      new_individual_tags.append('\n')
      dict_attributes2={"rdf:resource":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Product"}
      new_individual_tags.append(soupvdo.new_tag('rdf:type', attrs=dict_attributes2))
      new_individual_tags.append('\n')
      dict_attributes3 = {"rdf:resource" : "http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#ProdEnum"+cve_id}
      new_individual_tags.append(soupvdo.new_tag('untitled-ontology-4:hasProductEnumeration',attrs=dict_attributes3))
      new_individual_tags.append('\n')

      
      last_description_tag.insert_after(new_individual_tags)

      if len(cpenewlist)!=0:
        dict_attributesenum={"rdf:about":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#ProdEnum"+cve_id}
        new_individual_tagsenum=soupvdo.new_tag('owl:NamedIndividual', attrs=dict_attributesenum)
        new_individual_tagsenum.append('\n')
        dict_attributesenum2={"rdf:resource":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#ProductEnumeration"}
        new_individual_tagsenum.append(soupvdo.new_tag('rdf:type', attrs=dict_attributesenum2))
        new_individual_tagsenum.append('\n')
        dict_attributesenum3={"rdf:datatype":"http://www.w3.org/2001/XMLSchema#string"}
        for e in cpenewlist:
          valueNouveau = soupvdo.new_tag("untitled-ontology-4:values",attrs=dict_attributesenum3)
          valueNouveau.string = e
          new_individual_tagsenum.append(valueNouveau)
          new_individual_tagsenum.append('\n')
        last_description_tag.insert_after(new_individual_tagsenum)

        #productenumdata='<!-- http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#ProdEnum'+cve_id+' -->\n<owl:NamedIndividual rdf:about="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#ProdEnum'+cve_id+'">\n<rdf:type rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#ProductEnumeration"/>\n<untitled-ontology-4:values rdf:datatype="http://www.w3.org/2001/XMLSchema#string">'+cpenewlist[-1]+'</untitled-ontology-4:values>\n<untitled-ontology-4:values rdf:datatype="http://www.w3.org/2001/XMLSchema#string">'+cpenewlist[0]+'</untitled-ontology-4:values>\n</owl:NamedIndividual>'
      #productdata=''
      #productdata='<!-- http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Product'+cve_id+' -->\n<owl:NamedIndividual rdf:about="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Product'+cve_id+'">\n<rdf:type rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Product"/>\n<untitled-ontology-4:hasProductEnumeration rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#ProdEnum'+cve_id+'"/>\n</owl:NamedIndividual>'

      
      
      


      #print(new_individual_tagsact)
      # Save the modified OWL file
      with open(owl_file_path, 'w') as file:
          file.write(str(soupvdo))
      return 'yes'
  else:
      print(f"Failed to retrieve data. Status code: {response.status_code}")
      return 'no'
  
  #with open(cve_id+".txt", "a") as myfile:
  #    myfile.write(productenumdata+'\n'+productdata+'\n'+attackerdata+'\n'+actiondata+'\n'+iddata+'\n'+cvedata+'\n')
#Nouvelle approche
# Charger le fichier OWL
onto = get_ontology("/var/www/html/ADG/d3fend.owl").load()
off=[]
def takesubclassof(namefile,parentclass):
    # Ouvrir un fichier TSV pour écrire les données
    with open(namefile, mode='w') as file:
        writer = csv.writer(file, delimiter='\t')
        # Ecrire l'en-tête de colonne
        writer.writerow(["ID", "Nom"])

        # Compteur pour assigner des ID uniques
        id_counter = 1

        # Récupérer la classe parent
        parent_class = onto.search_one(iri = "*"+parentclass)

        # Parcourir toutes les sous-classes de la classe parent
        for sub_class in parent_class.subclasses():
            parent_class = onto.search_one(iri = "*"+sub_class.name)
            for p_class in parent_class.subclasses():
                # Écrire les données dans le fichier TSV
                if p_class not in off:
                    writer.writerow([id_counter, "http://d3fend.mitre.org/ontologies/d3fend.owl#"+p_class.name])
                    id_counter += 1
                    off.append(p_class)

#Nouvelle approche
#class SparqlQueries:
#    def __init__(self):
my_world1 = World()
my_world1.get_ontology("/var/www/html/ADG/d3fend.owl").load() #path to the owl file is given here
#sync_reasoner(my_world)  #reasoner is started and synchronized here
graph1 = my_world1.as_rdflib_graph()

def searchtech(techn):
    technique=[]
    sparql = """select ?a where{
                    <http://d3fend.mitre.org/ontologies/d3fend.owl#"""+techn+"""> <http://www.w3.org/2000/01/rdf-schema#label> ?a.
                }"""
    #query is being run
    resultsList = graph1.query(sparql)
    for row in resultsList:
        s = str(row['a'].toPython())
        technique.append(s)
    return technique

def searchimpact(techn):
    technique=[]
    sparql = """select ?a where{
                    <http://d3fend.mitre.org/ontologies/d3fend.owl#"""+techn+"""> <http://www.w3.org/2000/01/rdf-schema#label> ?a.
                    <http://d3fend.mitre.org/ontologies/d3fend.owl#"""+techn+"""> rdfs:subClassOf+ <http://d3fend.mitre.org/ontologies/d3fend.owl#ImpactTechnique> .
                }"""
    #query is being run
    resultsList = graph1.query(sparql)
    for row in resultsList:
        s = str(row['a'].toPython())
        technique.append(s)
    return technique

def searchpriv(techn):
    technique=[]
    sparql = """select ?a where{
                    <http://d3fend.mitre.org/ontologies/d3fend.owl#"""+techn+"""> <http://www.w3.org/2000/01/rdf-schema#label> ?a.
                    <http://d3fend.mitre.org/ontologies/d3fend.owl#"""+techn+"""> rdfs:subClassOf+ <http://d3fend.mitre.org/ontologies/d3fend.owl#PrivilegeEscalationTechnique> .
                }"""
    #query is being run
    resultsList = graph1.query(sparql)
    for row in resultsList:
        s = str(row['a'].toPython())
        technique.append(s)
    return technique
def cveiddata(gr,val):
    countermeasure=[]
    sparql = """SELECT ?im
              WHERE{
                    <"""+val+"""> <http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#hasIdentity> ?i .
                    ?i rdf:type <http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#VulnerabilityIdentifier> .
                    ?i <http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#value> ?im .
                }"""
    #query is being run
    resultsList = gr.query(sparql)
    for row in resultsList:
        s = str(row['im'].toPython())
        countermeasure.append(s)
    return countermeasure    

def searchar(t):
    artifact=[]
    sparql = """select Distinct ?l where{
          {
              ?sb rdfs:subClassOf ?of.
              ?of rdfs:subClassOf+ <http://d3fend.mitre.org/ontologies/d3fend.owl#OffensiveTechnique> .
              ?of <http://www.w3.org/2000/01/rdf-schema#label> '"""+t+"""' .
              ?sb ?p ?b .
              ?b rdfs:subClassOf* <http://d3fend.mitre.org/ontologies/d3fend.owl#Artifact> .
              ?b <http://www.w3.org/2000/01/rdf-schema#label> ?l .
          }
          UNION
          {
              ?of rdfs:subClassOf+ <http://d3fend.mitre.org/ontologies/d3fend.owl#OffensiveTechnique> .
              ?of <http://www.w3.org/2000/01/rdf-schema#label> '"""+t+"""' .
              ?of ?p ?b .
              ?b rdfs:subClassOf* <http://d3fend.mitre.org/ontologies/d3fend.owl#Artifact> .
              ?b <http://www.w3.org/2000/01/rdf-schema#label> ?l .
          }
        }"""
    #query is being run
    resultsList = graph1.query(sparql)
    for row in resultsList:
        s = str(row['l'].toPython())
        artifact.append(s)
    return artifact
def search(asset):
    countermeasure=[]
    propriete=[]
    sparql = """select ?label ?def ?desc ?p where {
    <http://d3fend.mitre.org/ontologies/d3fend.owl#"""+asset+"""> rdfs:subClassOf* ?class .
    ?class2 rdfs:subClassOf* <http://d3fend.mitre.org/ontologies/d3fend.owl#"""+asset+"""> .
        {
            select ?label ?def ?desc ?p where{
                {
                    ?def rdfs:subClassOf+ <http://d3fend.mitre.org/ontologies/d3fend.owl#DefensiveTechnique> .
                    ?def ?p ?class .
                    ?def rdfs:label ?label .
                    ?def <http://d3fend.mitre.org/ontologies/d3fend.owl#definition> ?desc .
                }
                UNION
                {
                    ?def rdfs:subClassOf+ <http://d3fend.mitre.org/ontologies/d3fend.owl#DefensiveTechnique> .
                    ?def ?p ?class2 .
                    ?def rdfs:label ?label .
                    ?def <http://d3fend.mitre.org/ontologies/d3fend.owl#definition> ?desc .
                }
            }
        }
    }"""
    #query is being run
    resultsList = graph1.query(sparql)
    for row in resultsList:
        s = str(row['label'].toPython())
        p = str(row['p'].toPython())
        countermeasure.append(s)
        propriete.append(s+","+p)
    return countermeasure, propriete

def searchartifact():
    countermeasure=[]
    sparql = """select ?a where{
                    ?ar rdfs:subClassOf+ <http://d3fend.mitre.org/ontologies/d3fend.owl#Artifact> .
                    ?ar <http://www.w3.org/2000/01/rdf-schema#label> ?a .
                }"""
    #query is being run
    resultsList = graph1.query(sparql)
    for row in resultsList:
        s = str(row['a'].toPython())
        countermeasure.append(s)
    return countermeasure

#Nouvelle approche
#class SparqlQueries:
#    def __init__(self):
my_world = World()
my_world.get_ontology("/var/www/html/ADG/rdfxmlgraph.owl").load() #path to the owl file is given here
#sync_reasoner(my_world)  #reasoner is started and synchronized here
graph = my_world.as_rdflib_graph()

def searchcontext():
    countermeasure=[]
    sparql = """select ?c where{
                    ?co rdf:type <http://www.semanticweb.org/keren/ontologies/2021/7/vdo#Context> .
                    ?co <http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#value> ?c .
                }"""
    #query is being run
    resultsList = graph.query(sparql)
    for row in resultsList:
        s = str(row['c'].toPython())
        countermeasure.append(s)
    return countermeasure

def searchimpacts():
    countermeasure=[]
    sparql = """select ?i where{
                    ?im rdf:type <http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#LogicalImpact> .
                    ?im <http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#value> ?i .
                }"""
    #query is being run
    resultsList = graph.query(sparql)
    for row in resultsList:
        s = str(row['i'].toPython())
        countermeasure.append(s)
    return countermeasure
logicalimpact=searchimpacts()

def searchmethod():
    countermeasure=[]
    sparql = """select ?m where{
                    ?me rdf:type <http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#ImpactMethod> .
                    ?me <http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#value> ?m .
                }"""
    #query is being run
    resultsList = graph.query(sparql)
    for row in resultsList:
        s = str(row['m'].toPython())
        countermeasure.append(s)
    return countermeasure

def searchard(t):
    artifact=[]
    sparql = """select Distinct ?l where{
                    ?of rdfs:subClassOf+ ?o .
                    ?o <http://www.w3.org/2000/01/rdf-schema#label> '""" +t+"""' .
                    ?of <http://www.w3.org/2000/01/rdf-schema#label> ?l .
                }"""
    #query is being run
    resultsList = graph1.query(sparql)
    for row in resultsList:
        s = str(row['l'].toPython())
        artifact.append(s)
    return artifact
# Matching process starts here
#Nouvelle approche
parent_class_nameexec = "OffensiveTechnique"
namefileexec='/var/www/html/ADG/offensive.tsv'
takesubclassof(namefileexec,parent_class_nameexec)
#Nouvelle approche
data = pd.read_csv("/var/www/html/ADG/offensive.tsv", sep="\t")
entitiesdef = [entity for entity in data["Nom"]]
impacttechnique=[]
imptechnique=[]
for entity in entitiesdef:
  tech=str(entity.split('#')[1])
  imptechnique=searchimpact(tech)
  privtechnique=searchpriv(tech)
  if len(imptechnique)!=0:
    impacttechnique.append(imptechnique)
  if len(privtechnique)!=0:
    impacttechnique.append(privtechnique)
for imp in impacttechnique:
  imptechnique.append(imp[0])
techniquedef=[]
for entity in entitiesdef:
  tech=str(entity.split('#')[1])
  technique=searchtech(tech)
  techniquedef.append(technique)

def askcveexist(val):
    countermeasure=[]
    sparql = """SELECT Distinct ?i
              WHERE{
                    ?i <http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#hasIdentity> <http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#"""+val+"""> .
                    ?im rdf:type <http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#VulnerabilityIdentifier> .
                }"""
    #query is being run
    resultsList = graph.query(sparql)
    for row in resultsList:
        s = str(row['i'].toPython())
        countermeasure.append(s)
    return countermeasure

def matchgraph(cve):
  #cveid="CVE-2023-6446"
  cveid=cve
  vdo = get_ontology("/var/www/html/ADG/rdfxmlgraph.owl").load()

  class_name = "Vulnerability"
  # Récupération de la classe
  #my_class = vdo.search_one(iri = "*" + class_name)
  # Récupération des individus de la classe
  entities = vdo.Vulnerability.instances()
  # Ouverture d'un fichier TSV pour écrire les résultats
  with open("/var/www/html/ADG/vdo.tsv", "w") as f:
      f.write("ID\tvulnerability\n")
      """for i, entity in enumerate(entities):
          print(entity)
          f.write("{}\t{}\n".format(i+1, "http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#"+entity.name))"""
      f.write("{}\t{}\n".format(1, "http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#CVE"+cveid))
  #Nouvelle approche
  datavdo = pd.read_csv("/var/www/html/ADG/vdo.tsv", sep="\t")
  entitiesvdo = [entity for entity in datavdo["vulnerability"]]
  offensivetech=[]
  for off in techniquedef:
    offensivetech.append(off[0])
  corpusoff=[]
  corpus=[]
  for item in offensivetech:
    if item not in imptechnique:
      split_words=item.split()
      corpus.append(split_words)
      corpusoff.append(split_words)
  corpusimp=[]
  for item in imptechnique:
      split_words=item.split()
      corpus.append(split_words)
      corpusimp.append(split_words)
  artifact=searchartifact()

  corpusart=[]
  for item in artifact:
      split_words=item.split()
      corpus.append(split_words)
      corpusart.append(split_words)
  impactmethod=searchmethod()
  for item in impactmethod:
      split_words=item.split()
      corpus.append(split_words)
      corpusoff.append(split_words)
  context=searchcontext()
  for item in context:
      split_words=item.split()
      corpus.append(split_words)    
      corpusart.append(split_words)

  #from gensim.models import Word2Vec

  # Entraînement du modèle word2vec
  model = gensim.models.Word2Vec(corpusart, vector_size=200, window=5, min_count=1, workers=4, epochs=30)

  # Enregistrement du modèle
  model.save("/var/www/html/ADG/word2vec.model")
  #from gensim.models import Word2Vec

  # Entraînement du modèle word2vec
  modelart = gensim.models.Word2Vec(corpusart, vector_size=200, window=5, min_count=1, workers=4, epochs=30)

  # Enregistrement du modèle
  modelart.save("/var/www/html/ADG/word2vecart.model")


  # Train a bigram detector.
  bigram_transformer = Phrases(corpusart)
  # Apply the trained MWE detector to a corpus, using the result to train a Word2vec model.
  modela = gensim.models.Word2Vec(bigram_transformer[corpusart], min_count=1)
  # Enregistrement du modèle
  modela.save("/var/www/html/ADG/word2veca.model")
  modeloff = gensim.models.Word2Vec(corpusoff, vector_size=250, window=5, min_count=1, workers=20, epochs=50)

  modeloff.save("/var/www/html/ADG/word2vecoff.model")
  modelimp = gensim.models.Word2Vec(corpusimp, vector_size=250, window=5, min_count=1, workers=20, epochs=150)

  modelimp.save("/var/www/html/ADG/word2vecimp.model")
  askres=askcveexist(cveid)
  print(cveid,askres)
  #print(askres)

  if len(askres)!=0:
    
    transformer = RDF2VecTransformer(walkers=[RandomWalker(4, 1, with_reverse=False, n_jobs=2)],
                                  verbose=1,
                                  embedder=Word2Vec(sentences=corpus))
    embeddingsdef, literalsdef = transformer.fit_transform(
        KG(
            "/var/www/html/ADG/d3fend.owl",
          literals=[
                [
                    "http://d3fend.mitre.org/ontologies/d3fend.owl#executes",
                    "http://www.w3.org/2000/01/rdf-schema#label"
                ],
                [
                    "http://d3fend.mitre.org/ontologies/d3fend.owl#invokes",
                    "http://www.w3.org/2000/01/rdf-schema#label"
                ],
                [
                    "http://d3fend.mitre.org/ontologies/d3fend.owl#may-modify",
                    "http://www.w3.org/2000/01/rdf-schema#label"
                ],
                [
                    "http://d3fend.mitre.org/ontologies/d3fend.owl#modifies",
                    "http://www.w3.org/2000/01/rdf-schema#label"
                ],
                [
                    "http://d3fend.mitre.org/ontologies/d3fend.owl#accesses",
                    "http://www.w3.org/2000/01/rdf-schema#label"
                ],
                [
                    "http://d3fend.mitre.org/ontologies/d3fend.owl#may-access",
                    "http://www.w3.org/2000/01/rdf-schema#label"
                ],
                [
                    "http://d3fend.mitre.org/ontologies/d3fend.owl#runs",
                    "http://www.w3.org/2000/01/rdf-schema#label"
                ],
                [
                    "http://d3fend.mitre.org/ontologies/d3fend.owl#adds",
                    "http://www.w3.org/2000/01/rdf-schema#label"
                ],
                [
                    "http://d3fend.mitre.org/ontologies/d3fend.owl#may-add",
                    "http://www.w3.org/2000/01/rdf-schema#label"
                ],
                [
                    "http://d3fend.mitre.org/ontologies/d3fend.owl#produces",
                    "http://www.w3.org/2000/01/rdf-schema#label"
                ],
                [
                    "http://d3fend.mitre.org/ontologies/d3fend.owl#creates",
                    "http://www.w3.org/2000/01/rdf-schema#label"
                ],
                [
                    "http://d3fend.mitre.org/ontologies/d3fend.owl#may-create",
                    "http://www.w3.org/2000/01/rdf-schema#label"
                ],
                [
                    "http://d3fend.mitre.org/ontologies/d3fend.owl#uses",
                    "http://www.w3.org/2000/01/rdf-schema#label"
                ],
                [
                    "http://d3fend.mitre.org/ontologies/d3fend.owl#copies",
                    "http://www.w3.org/2000/01/rdf-schema#label"
                ],
                [
                    "http://d3fend.mitre.org/ontologies/d3fend.owl#may-transfer",
                    "http://www.w3.org/2000/01/rdf-schema#label"
                ],
                [
                    "http://d3fend.mitre.org/ontologies/d3fend.owl#reads",
                    "http://www.w3.org/2000/01/rdf-schema#label"
                ],
                [
                    "http://d3fend.mitre.org/ontologies/d3fend.owl#loads",
                    "http://www.w3.org/2000/01/rdf-schema#label"
                ],
                [
                    "http://d3fend.mitre.org/ontologies/d3fend.owl#may-invoke",
                    "http://www.w3.org/2000/01/rdf-schema#label"
                ],
                [
                    "http://d3fend.mitre.org/ontologies/d3fend.owl#queries",
                    "http://www.w3.org/2000/01/rdf-schema#label"
                ],
                [
                    "http://d3fend.mitre.org/ontologies/d3fend.owl#interprets",
                    "http://www.w3.org/2000/01/rdf-schema#label"
                ],
                [
                    "http://d3fend.mitre.org/ontologies/d3fend.owl#installs",
                    "http://www.w3.org/2000/01/rdf-schema#label"
                ],
                [
                    "http://d3fend.mitre.org/ontologies/d3fend.owl#hides",
                    "http://www.w3.org/2000/01/rdf-schema#label"
                ],
                [
                    "http://d3fend.mitre.org/ontologies/d3fend.owl#injects",
                    "http://www.w3.org/2000/01/rdf-schema#label"
                ],
                [
                    "http://d3fend.mitre.org/ontologies/d3fend.owl#forges",
                    "http://www.w3.org/2000/01/rdf-schema#label"
                ],
                [
                    "http://d3fend.mitre.org/ontologies/d3fend.owl#connects",
                    "http://www.w3.org/2000/01/rdf-schema#label"
                ],
                [
                    "http://d3fend.mitre.org/ontologies/d3fend.owl#unmounts",
                    "http://www.w3.org/2000/01/rdf-schema#label"
                ],
            ],
        ),
        entitiesdef
    )
    transformer = RDF2VecTransformer(walkers=[RandomWalker(4, 1, with_reverse=False, n_jobs=2)],
                                    verbose=1,
                                    embedder=Word2Vec(sentences=corpus))
    embeddingsvdo, literalsvdo = transformer.fit_transform(
        KG(
            "/var/www/html/ADG/rdfxmlgraph.owl",
            #skip_predicates={"www.w3.org/1999/02/22-rdf-syntax-ns#type"},
          literals=[
                [
                    "http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#hasScenario",
                    "http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#hasAction",
                    "http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#hasImpactMethod",
                    "http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#value"
                ],
                [
                    "http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#hasScenario",
                    "http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#hasAction",
                    "http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#resultsInImpact",
                    "http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#hasLogicalImpact",
                    "http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#value"
                ],
                [
                    "http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#hasScenario",
                    "http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#hasAction",
                    "http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#affectsContext",
                    "http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#value"
                ],
            ],
        ),
        entitiesvdo,
    )
    listevul=[]
    for lit in range(len(literalsvdo)):
      if type(literalsvdo[lit][1]) is tuple:
        for imp in literalsvdo[lit][1]:
          if type(literalsvdo[lit][0]) is tuple:
            for met in literalsvdo[lit][0]:
              litvdo=[entitiesvdo[lit],str(met),str(imp),literalsvdo[lit][2]]
              listevul.append(litvdo)
          else:
            litvdo=[entitiesvdo[lit],literalsvdo[lit][0],str(imp),literalsvdo[lit][2]]
            listevul.append(litvdo)
      else:
        if type(literalsvdo[lit][0]) is tuple:
          for met in literalsvdo[lit][0]:
            litvdo=[entitiesvdo[lit],str(met),literalsvdo[lit][1],literalsvdo[lit][2]]
            listevul.append(litvdo)
        else:
            litvdo=[entitiesvdo[lit],literalsvdo[lit][0],literalsvdo[lit][1],literalsvdo[lit][2]]
            listevul.append(litvdo)

    listresult=[]
    listresult2=[]
    modeloff = gensim.models.Word2Vec.load("/var/www/html/ADG/word2vecoff.model")
    modelimp = gensim.models.Word2Vec.load("/var/www/html/ADG/word2vecimp.model")
    for vul in range(len(listevul)):
      sentences_similarity = np.zeros(len(offensivetech))
      sentences_similarity2 = np.zeros(len(offensivetech))
      for idx, sentence in enumerate(offensivetech):
        method=listevul[vul][1]
        impact=listevul[vul][2]
        sentence_words = sentence.split()
        for word in sentence_words:
          sim_to_sentence = 0
          sim_to_sentence2 = 0
          if type(impact)==str:
            logimpact=impact
            for imptarget in impact.split():
              if imptarget=="Shutdown" or imptarget=="Reboot":
                imptarget="Shutdown/Reboot"
              try:
                  sim_to_sentence2 += modelimp.wv.similarity(word, imptarget)
              except KeyError:
                  pass # ignore words that aren't in vocabulary
          if type(method)==str:
            for target in method.split():
                try:
                    sim_to_sentence += modeloff.wv.similarity(word, target)
                except KeyError:
                    pass # ignore words that aren't in vocabulary
          if type(impact)==float:
            logimpact=impact
          sim_to_sentence /= len(sentence_words)
          sim_to_sentence2 /= len(sentence_words)
        sentences_similarity[idx] += sim_to_sentence
        sentences_similarity2[idx] += sim_to_sentence2
      result = list(zip(sentences_similarity, offensivetech))
      result=heapq.nlargest(1, result, key=lambda x:x[0])

      result2 = list(zip(sentences_similarity2, offensivetech))
      result2=heapq.nlargest(1, result2, key=lambda x:x[0])
      jsonresult={'CVEID': listevul[vul][0],'ImpactMethod':listevul[vul][1],'LogicalImpact':logimpact, 'Context':listevul[vul][3], 'result': result}
      listresult.append(jsonresult)
      jsonresult2={'CVEID': listevul[vul][0],'ImpactMethod':listevul[vul][1],'LogicalImpact':logimpact, 'Context':listevul[vul][3], 'result': result2}
      listresult2.append(jsonresult2)
      #Modifier pour que ça prenne l'un ou l'autre entre impact et méthode sans tenir compte du max, il suffit que le score soit suppérieur à 0.2
    listresult4=[]
    for res in listresult:
      for res2 in listresult2:
        if res['CVEID']==res2['CVEID']:
          #if  max(res['result'][0][0],res2['result'][0][0])>0.15:
          if res['result'][0][0]>0.1:
            #if max(res['result'][0][0],res2['result'][0][0])==res['result'][0][0]:
              #matching = [s for s in offens if res['result'][0][1] in s]
              #print(matching)
              result={'CVEID':res['CVEID'], 'Context':res['Context'], 'Method or Impact':res['ImpactMethod'],'OffensiveTechnique':res['result'][0][1]}
              if result not in listresult4:
                listresult4.append(result)
              #res['OffensiveTechnique'] = res['result'][0][1]
          if res2['result'][0][0]>0.1:
            #else:
              #matching = [s for s in offens if res2['result'][0][1] in s]
              #print(matching)
              result={'CVEID':res2['CVEID'], 'Context':res2['Context'], 'Method or Impact':res2['LogicalImpact'],'OffensiveTechnique':res2['result'][0][1]}
              if result not in listresult4:
                listresult4.append(result)
              #res['OffensiveTechnique'] = res2['result'][0][1]
    listresult6=[]
    for e in range(len(listresult4)):
      if listresult4[e]["CVEID"]==listresult4[e-1]["CVEID"] and listresult4[e]["OffensiveTechnique"]==listresult4[e-1]["OffensiveTechnique"]:
        listresult6.append(listresult4[e])
      """if e not in listresult3:
        cve=e["CVEID"]
        listresult3.append(e)"""
    if len(listresult4)!=1:
      listresultfinal = [i for i in listresult4 if i not in listresult6]
    else:
      listresultfinal=listresult6



    for r in range(len(listresultfinal)):
      artifacts=[]
      technique=str(listresultfinal[r]['OffensiveTechnique'])
      art=searchar(technique)
      if len(art)>0:
        for a in art:
          if a=='Digital Artifact' and len(art)==1:
            artifactss=searchard(a)
            modelart = gensim.models.Word2Vec.load("/var/www/html/ADG/word2vecart.model")
            sentences_similarity3 = np.zeros(len(artifactss))
            for idx, sentence in enumerate(artifactss):
              context=listresultfinal[r]['Context']
              sentence_words3 = sentence.split()
              for word in sentence_words3:
                sim_to_sentence3 = 0
                for target in context.split():
                    try:
                        sim_to_sentence3 += modelart.wv.similarity(word, target)
                    except KeyError:
                        pass # ignore words that aren't in vocabulary
                sim_to_sentence3 /= len(sentence_words3)
              sentences_similarity3[idx] += sim_to_sentence3
              if len(set(sentence_words3).intersection(context.split()))>=len(context.split())-1:
                sentences_similarity3[idx]=sentences_similarity3[idx]+0.5
            result3 = list(zip(sentences_similarity3, artifactss))
            for z in result3:
              intersec=set(z[1].split()).intersection(context.split())
            result3=heapq.nlargest(5, result3, key=lambda x:x[0])
            artifacts.append(result3[0][1])
          else:
            if a!='Digital Artifact':
              artifacts.append(a)
      else:
        artifactss=searchard('Digital Artifact')
        #print(artifactss)
        modelart = gensim.models.Word2Vec.load("/var/www/html/ADG/word2vecart.model")
        sentences_similarity3 = np.zeros(len(artifactss))
        for idx, sentence in enumerate(artifactss):
          context=listresultfinal[r]['Context']
          sentence_words3 = sentence.split()
          for word in sentence_words3:
            sim_to_sentence3 = 0
            #print(context)
            if type(context)==str:
              for target in context.split():
                  try:
                      sim_to_sentence3 += modelart.wv.similarity(word, target)
                  except KeyError:
                      pass # ignore words that aren't in vocabulary
              sim_to_sentence3 /= len(sentence_words3)
            sentences_similarity3[idx] += sim_to_sentence3
          if type(context)==str:
            if len(set(sentence_words3).intersection(context.split()))>=len(context.split())-1:
              sentences_similarity3[idx]=sentences_similarity3[idx]+0.5
        result3 = list(zip(sentences_similarity3, artifactss))
        for z in result3:
          if type(context)==str:
            intersec=set(z[1].split()).intersection(context.split())
        result3=heapq.nlargest(5, result3, key=lambda x:x[0])
        artifacts.append(result3[0][1])
      listresultfinal[r]['Artifact'] = artifacts
    modelart = gensim.models.Word2Vec.load("/var/www/html/ADG/word2vecart.model")
    for vul in range(len(listresultfinal)):
      sentences_similarity3 = np.zeros(len(listresultfinal[vul]['Artifact']))
      for idx, sentence in enumerate(listresultfinal[vul]['Artifact']):
        #print(sentences_similarity,sentence)
        context=listresultfinal[vul]['Context']
        #print(impact)
        #print(context,idx,sentence)
        sentence_words3 = sentence.split()
        #print(sentence_words)
        for word in sentence_words3:
          sim_to_sentence3 = 0
          #print(context)
          if type(context)==str:
            for target in context.split():
                #print(idx,target,word)
                if type(target)!=float:
                  try:
                      sim_to_sentence3 += modelart.wv.similarity(word, target)
                  except KeyError:
                      pass # ignore words that aren't in vocabulary
            sim_to_sentence3 /= len(sentence_words3)
        sentences_similarity3[idx] += sim_to_sentence3
      result3 = list(zip(sentences_similarity3, listresultfinal[vul]['Artifact']))
      #result3=heapq.nlargest(1, result3, key=lambda x:x[0])

    #Nouvelle approche
    removeart=[]
    removecounter=[]
    datasetcounter=[]
    countermeasure=[]
    propriete=[]
    phase=""
    category=""
    eradicationverb=["http://d3fend.mitre.org/ontologies/d3fend.owl#deletes","http://d3fend.mitre.org/ontologies/d3fend.owl#evicts","http://d3fend.mitre.org/ontologies/d3fend.owl#terminates","http://d3fend.mitre.org/ontologies/d3fend.owl#may-evict"]
    #identificationverb=["http://d3fend.mitre.org/ontologies/d3fend.owl#monitors","http://d3fend.mitre.org/ontologies/d3fend.owl#detects","http://d3fend.mitre.org/ontologies/d3fend.owl#analyzes", "http://d3fend.mitre.org/ontologies/d3fend.owl#verifies", "http://d3fend.mitre.org/ontologies/d3fend.owl#identifies", "http://d3fend.mitre.org/ontologies/d3fend.owl#evaluates"]
    identificationverb=["http://d3fend.mitre.org/ontologies/d3fend.owl#evaluates","http://d3fend.mitre.org/ontologies/d3fend.owl#validates","http://d3fend.mitre.org/ontologies/d3fend.owl#monitors","http://d3fend.mitre.org/ontologies/d3fend.owl#detects","http://d3fend.mitre.org/ontologies/d3fend.owl#neutralizes", "http://d3fend.mitre.org/ontologies/d3fend.owl#verifies","http://d3fend.mitre.org/ontologies/d3fend.owl#analyzes","http://d3fend.mitre.org/ontologies/d3fend.owl#restricts","http://d3fend.mitre.org/ontologies/d3fend.owl#spoofs","http://d3fend.mitre.org/ontologies/d3fend.owl#deceives-with"]
    containmentverb=["http://d3fend.mitre.org/ontologies/d3fend.owl#updates","http://d3fend.mitre.org/ontologies/d3fend.owl#suspends","http://d3fend.mitre.org/ontologies/d3fend.owl#may-contain","http://d3fend.mitre.org/ontologies/d3fend.owl#use-limits","http://d3fend.mitre.org/ontologies/d3fend.owl#obfuscates","http://d3fend.mitre.org/ontologies/d3fend.owl#disables","http://d3fend.mitre.org/ontologies/d3fend.owl#may-disable","http://d3fend.mitre.org/ontologies/d3fend.owl#use-limits","http://d3fend.mitre.org/ontologies/d3fend.owl#encrypts","http://d3fend.mitre.org/ontologies/d3fend.owl#limits","http://d3fend.mitre.org/ontologies/d3fend.owl#authenticates","http://d3fend.mitre.org/ontologies/d3fend.owl#filters","http://d3fend.mitre.org/ontologies/d3fend.owl#isolates","http://d3fend.mitre.org/ontologies/d3fend.owl#hardens","http://d3fend.mitre.org/ontologies/d3fend.owl#blocks"]
    #containmentverb=["http://d3fend.mitre.org/ontologies/d3fend.owl#validates","http://d3fend.mitre.org/ontologies/d3fend.owl#may-contain","http://d3fend.mitre.org/ontologies/d3fend.owl#use-limits","http://d3fend.mitre.org/ontologies/d3fend.owl#encrypts","http://d3fend.mitre.org/ontologies/d3fend.owl#restricts","http://d3fend.mitre.org/ontologies/d3fend.owl#limits""http://d3fend.mitre.org/ontologies/d3fend.owl#authenticates","http://d3fend.mitre.org/ontologies/d3fend.owl#filters","http://d3fend.mitre.org/ontologies/d3fend.owl#isolates","http://d3fend.mitre.org/ontologies/d3fend.owl#hardens","http://d3fend.mitre.org/ontologies/d3fend.owl#blocks","http://d3fend.mitre.org/ontologies/d3fend.owl#spoofs","http://d3fend.mitre.org/ontologies/d3fend.owl#deceives-with"]
    recoveryverb=["http://d3fend.mitre.org/ontologies/d3fend.owl#strengthens","http://d3fend.mitre.org/ontologies/d3fend.owl#enables","http://d3fend.mitre.org/ontologies/d3fend.owl#regenerates","http://d3fend.mitre.org/ontologies/d3fend.owl#restores"]
    preparationverb=["http://d3fend.mitre.org/ontologies/d3fend.owl#may-access","http://d3fend.mitre.org/ontologies/d3fend.owl#manages"]
    for result in listresultfinal:
        for res in result['Artifact']:
            request=search(res.replace(" ", ""))
            countermeasure=[i for n, i in enumerate(request[0]) if i not in request[0][:n]]
            propriete=[i for n, i in enumerate(request[1]) if i not in request[1][:n]]
            #print(res,len(propriete),len(countermeasure))
            for count in range(len(countermeasure)):
                if res.find("File") >= 0 or res.find("Script") >= 0:
                    category="File"
                else:
                  if res.find("Process") >= 0:
                    category="Process"
                  else:
                    if res.find("Email") >= 0:
                      category="Email"
                    else:
                      if res.find("Network") >= 0 or res.find("Address") >= 0 or res.find("IP") >= 0 or res.find("Domain") >= 0 or res.find("URL") >= 0 or res.find("Domain") >= 0 or res.find("Log") >= 0:
                        category="Network"
                      else:
                        if res.find("User") >= 0 or res.find("Token") >= 0 or res.find("Credential") >= 0 or res.find("Session") >= 0:
                          category="Identity"
                        else:
                          if res.find("Service") >= 0 or res.find("Key") >= 0:
                            category="Configuration"
                          else:
                            category="General"
                #print(res,index)
                #print(vdo.search_one(iri = "*"+result["CVEID"].split("#")[1]).hasIdentity[0].value[0])
                #print(vdo.search_one(iri = "*"+result["CVEID"]))
                ontos = World()
                ontos.get_ontology("/var/www/html/ADG/rdfxmlgraph.owl").load() #path to the owl file is given here
                #sync_reasoner(my_world)  #reasoner is started and synchronized here
                g = ontos.as_rdflib_graph()
                cveid=cveiddata(g,result["CVEID"])[0]
                if propriete[count].split(',')[1] in eradicationverb:
                  phase="Eradication"
                  datasetcounter.append({'CVEID':cveid, 'Method or Impact':result['Method or Impact'], 'Context':result['Context'], 'Artifact':res, 'Countermeasure':countermeasure[count], 'Phase':phase, 'Category':category})
                  phase=""
                else:
                  if propriete[count].split(',')[1] in identificationverb:
                    phase="Identification"
                    #cveid=vdo.search_one(iri = "*"+result["CVEID"].split("#")[1]).hasIdentity[0].value[0]
                    datasetcounter.append({'CVEID':cveid, 'Method or Impact':result['Method or Impact'], 'Context':result['Context'], 'Context':result['Context'], 'Artifact':res, 'Countermeasure':countermeasure[count], 'Phase':phase, 'Category':category})
                    phase=""
                  else:
                    if propriete[count].split(',')[1] in containmentverb:
                      phase="Containment"
                      #cveid=vdo.search_one(iri = "*"+result["CVEID"].split("#")[1]).hasIdentity[0].value[0]
                      datasetcounter.append({'CVEID':cveid, 'Method or Impact':result['Method or Impact'], 'Context':result['Context'], 'Context':result['Context'], 'Artifact':res, 'Countermeasure':countermeasure[count], 'Phase':phase, 'Category':category})
                      phase=""
                    else:
                      if propriete[count].split(',')[1] in recoveryverb:
                        phase="Recovery"
                        #cveid=vdo.search_one(iri = "*"+result["CVEID"].split("#")[1]).hasIdentity[0].value[0]
                        datasetcounter.append({'CVEID':cveid, 'Method or Impact':result['Method or Impact'], 'Context':result['Context'], 'Context':result['Context'], 'Artifact':res, 'Countermeasure':countermeasure[count], 'Phase':phase, 'Category':category})
                        phase=""
                      else:
                        if propriete[count].split(',')[1] in preparationverb:
                          phase="Preparation"
                          #cveid=vdo.search_one(iri = "*"+result["CVEID"].split("#")[1]).hasIdentity[0].value[0]
                          datasetcounter.append({'CVEID':cveid, 'Method or Impact':result['Method or Impact'], 'Context':result['Context'], 'Context':result['Context'], 'Artifact':res, 'Countermeasure':countermeasure[count], 'Phase':phase, 'Category':category})
                          phase=""
    #output
    #Nouvelle approche
    #tsv_file = open("countermeasureexec.tsv", "w")
    #tsv_writer = csv.writer(tsv_file, delimiter='\t')
    #print(datasetcounter)
    #tsv_writer.writerow(datasetcounter[0].keys()) # write the header

    #for row in datasetcounter: # write data rows
        #tsv_writer.writerow(row.values())

    #tsv_file.close()
    # Convert JSON objects to a list of lists
    data_to_write = [
        [item["CVEID"], str(item["Method or Impact"]), item["Context"], item["Artifact"], item["Countermeasure"], item["Phase"], item["Category"]] for item in datasetcounter
    ]

    # File path to the existing TSV file
    file_path = '/var/www/html/ADG/res7.tsv'

    # Open the file in append mode
    with open(file_path, 'a', newline='') as file:
        writer = csv.writer(file, delimiter='\t')
        writer.writerows(data_to_write)
  else:
    #executer extraction puis faire plongement de graphe
    print("ok")
    response=extractcve(cveid)
    if response=='yes':
      vdo1 = get_ontology("/var/www/html/ADG/rdfxmlgraph.owl").load()

      class_name = "Vulnerability"
      # Récupération de la classe
      #my_class = vdo.search_one(iri = "*" + class_name)
      # Récupération des individus de la classe
      entities = vdo1.Vulnerability.instances()
      # Ouverture d'un fichier TSV pour écrire les résultats
      with open("/var/www/html/ADG/vdo.tsv", "w") as f:
          f.write("ID\tvulnerability\n")
          """for i, entity in enumerate(entities):
              print(entity)
              f.write("{}\t{}\n".format(i+1, "http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#"+entity.name))"""
          f.write("{}\t{}\n".format(1, "http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#CVE"+cveid))
      #Nouvelle approche
      datavdo = pd.read_csv("./vdo.tsv", sep="\t")
      entitiesvdo = [entity for entity in datavdo["vulnerability"]]
      transformer = RDF2VecTransformer(walkers=[RandomWalker(4, 1, with_reverse=False, n_jobs=2)],
                                    verbose=1,
                                    embedder=Word2Vec(sentences=corpus))
      embeddingsdef, literalsdef = transformer.fit_transform(
          KG(
              "/var/www/html/ADG/d3fend.owl",
            literals=[
                  [
                      "http://d3fend.mitre.org/ontologies/d3fend.owl#executes",
                      "http://www.w3.org/2000/01/rdf-schema#label"
                  ],
                  [
                      "http://d3fend.mitre.org/ontologies/d3fend.owl#invokes",
                      "http://www.w3.org/2000/01/rdf-schema#label"
                  ],
                  [
                      "http://d3fend.mitre.org/ontologies/d3fend.owl#may-modify",
                      "http://www.w3.org/2000/01/rdf-schema#label"
                  ],
                  [
                      "http://d3fend.mitre.org/ontologies/d3fend.owl#modifies",
                      "http://www.w3.org/2000/01/rdf-schema#label"
                  ],
                  [
                      "http://d3fend.mitre.org/ontologies/d3fend.owl#accesses",
                      "http://www.w3.org/2000/01/rdf-schema#label"
                  ],
                  [
                      "http://d3fend.mitre.org/ontologies/d3fend.owl#may-access",
                      "http://www.w3.org/2000/01/rdf-schema#label"
                  ],
                  [
                      "http://d3fend.mitre.org/ontologies/d3fend.owl#runs",
                      "http://www.w3.org/2000/01/rdf-schema#label"
                  ],
                  [
                      "http://d3fend.mitre.org/ontologies/d3fend.owl#adds",
                      "http://www.w3.org/2000/01/rdf-schema#label"
                  ],
                  [
                      "http://d3fend.mitre.org/ontologies/d3fend.owl#may-add",
                      "http://www.w3.org/2000/01/rdf-schema#label"
                  ],
                  [
                      "http://d3fend.mitre.org/ontologies/d3fend.owl#produces",
                      "http://www.w3.org/2000/01/rdf-schema#label"
                  ],
                  [
                      "http://d3fend.mitre.org/ontologies/d3fend.owl#creates",
                      "http://www.w3.org/2000/01/rdf-schema#label"
                  ],
                  [
                      "http://d3fend.mitre.org/ontologies/d3fend.owl#may-create",
                      "http://www.w3.org/2000/01/rdf-schema#label"
                  ],
                  [
                      "http://d3fend.mitre.org/ontologies/d3fend.owl#uses",
                      "http://www.w3.org/2000/01/rdf-schema#label"
                  ],
                  [
                      "http://d3fend.mitre.org/ontologies/d3fend.owl#copies",
                      "http://www.w3.org/2000/01/rdf-schema#label"
                  ],
                  [
                      "http://d3fend.mitre.org/ontologies/d3fend.owl#may-transfer",
                      "http://www.w3.org/2000/01/rdf-schema#label"
                  ],
                  [
                      "http://d3fend.mitre.org/ontologies/d3fend.owl#reads",
                      "http://www.w3.org/2000/01/rdf-schema#label"
                  ],
                  [
                      "http://d3fend.mitre.org/ontologies/d3fend.owl#loads",
                      "http://www.w3.org/2000/01/rdf-schema#label"
                  ],
                  [
                      "http://d3fend.mitre.org/ontologies/d3fend.owl#may-invoke",
                      "http://www.w3.org/2000/01/rdf-schema#label"
                  ],
                  [
                      "http://d3fend.mitre.org/ontologies/d3fend.owl#queries",
                      "http://www.w3.org/2000/01/rdf-schema#label"
                  ],
                  [
                      "http://d3fend.mitre.org/ontologies/d3fend.owl#interprets",
                      "http://www.w3.org/2000/01/rdf-schema#label"
                  ],
                  [
                      "http://d3fend.mitre.org/ontologies/d3fend.owl#installs",
                      "http://www.w3.org/2000/01/rdf-schema#label"
                  ],
                  [
                      "http://d3fend.mitre.org/ontologies/d3fend.owl#hides",
                      "http://www.w3.org/2000/01/rdf-schema#label"
                  ],
                  [
                      "http://d3fend.mitre.org/ontologies/d3fend.owl#injects",
                      "http://www.w3.org/2000/01/rdf-schema#label"
                  ],
                  [
                      "http://d3fend.mitre.org/ontologies/d3fend.owl#forges",
                      "http://www.w3.org/2000/01/rdf-schema#label"
                  ],
                  [
                      "http://d3fend.mitre.org/ontologies/d3fend.owl#connects",
                      "http://www.w3.org/2000/01/rdf-schema#label"
                  ],
                  [
                      "http://d3fend.mitre.org/ontologies/d3fend.owl#unmounts",
                      "http://www.w3.org/2000/01/rdf-schema#label"
                  ],
              ],
          ),
          entitiesdef
      )
      transformer = RDF2VecTransformer(walkers=[RandomWalker(4, 1, with_reverse=False, n_jobs=2)],
                                      verbose=1,
                                      embedder=Word2Vec(sentences=corpus))
      embeddingsvdo, literalsvdo = transformer.fit_transform(
          KG(
              "/var/www/html/ADG/rdfxmlgraph.owl",
              #skip_predicates={"www.w3.org/1999/02/22-rdf-syntax-ns#type"},
            literals=[
                  [
                      "http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#hasScenario",
                      "http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#hasAction",
                      "http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#hasImpactMethod",
                      "http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#value"
                  ],
                  [
                      "http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#hasScenario",
                      "http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#hasAction",
                      "http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#resultsInImpact",
                      "http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#hasLogicalImpact",
                      "http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#value"
                  ],
                  [
                      "http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#hasScenario",
                      "http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#hasAction",
                      "http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#affectsContext",
                      "http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#value"
                  ],
              ],
          ),
          entitiesvdo,
      )
      print(entitiesvdo)
      listevul=[]
      for lit in range(len(literalsvdo)):
        if type(literalsvdo[lit][1]) is tuple:
          for imp in literalsvdo[lit][1]:
            if type(literalsvdo[lit][0]) is tuple:
              for met in literalsvdo[lit][0]:
                litvdo=[entitiesvdo[lit],str(met),str(imp),literalsvdo[lit][2]]
                listevul.append(litvdo)
            else:
              litvdo=[entitiesvdo[lit],literalsvdo[lit][0],str(imp),literalsvdo[lit][2]]
              listevul.append(litvdo)
        else:
          if type(literalsvdo[lit][0]) is tuple:
            for met in literalsvdo[lit][0]:
              litvdo=[entitiesvdo[lit],str(met),literalsvdo[lit][1],literalsvdo[lit][2]]
              listevul.append(litvdo)
          else:
              litvdo=[entitiesvdo[lit],literalsvdo[lit][0],literalsvdo[lit][1],literalsvdo[lit][2]]
              listevul.append(litvdo)

      listresult=[]
      listresult2=[]
      modeloff = gensim.models.Word2Vec.load("/var/www/html/ADG/word2vecoff.model")
      modelimp = gensim.models.Word2Vec.load("/var/www/html/ADG/word2vecimp.model")
      for vul in range(len(listevul)):
        sentences_similarity = np.zeros(len(offensivetech))
        sentences_similarity2 = np.zeros(len(offensivetech))
        for idx, sentence in enumerate(offensivetech):
          method=listevul[vul][1]
          impact=listevul[vul][2]
          sentence_words = sentence.split()
          for word in sentence_words:
            sim_to_sentence = 0
            sim_to_sentence2 = 0
            if type(impact)==str:
              logimpact=impact
              for imptarget in impact.split():
                if imptarget=="Shutdown" or imptarget=="Reboot":
                  imptarget="Shutdown/Reboot"
                try:
                    sim_to_sentence2 += modelimp.wv.similarity(word, imptarget)
                except KeyError:
                    pass # ignore words that aren't in vocabulary
            if type(method)==str:
              for target in method.split():
                  try:
                      sim_to_sentence += modeloff.wv.similarity(word, target)
                  except KeyError:
                      pass # ignore words that aren't in vocabulary
            if type(impact)==float:
              logimpact=impact
            sim_to_sentence /= len(sentence_words)
            sim_to_sentence2 /= len(sentence_words)
          sentences_similarity[idx] += sim_to_sentence
          sentences_similarity2[idx] += sim_to_sentence2
        result = list(zip(sentences_similarity, offensivetech))
        result=heapq.nlargest(1, result, key=lambda x:x[0])

        result2 = list(zip(sentences_similarity2, offensivetech))
        result2=heapq.nlargest(1, result2, key=lambda x:x[0])
        jsonresult={'CVEID': listevul[vul][0],'ImpactMethod':listevul[vul][1],'LogicalImpact':logimpact, 'Context':listevul[vul][3], 'result': result}
        listresult.append(jsonresult)
        jsonresult2={'CVEID': listevul[vul][0],'ImpactMethod':listevul[vul][1],'LogicalImpact':logimpact, 'Context':listevul[vul][3], 'result': result2}
        listresult2.append(jsonresult2)
        #Modifier pour que ça prenne l'un ou l'autre entre impact et méthode sans tenir compte du max, il suffit que le score soit suppérieur à 0.2
      listresult4=[]
      for res in listresult:
        for res2 in listresult2:
          if res['CVEID']==res2['CVEID']:
            #if  max(res['result'][0][0],res2['result'][0][0])>0.15:
            if res['result'][0][0]>0.1:
              #if max(res['result'][0][0],res2['result'][0][0])==res['result'][0][0]:
                #matching = [s for s in offens if res['result'][0][1] in s]
                #print(matching)
                result={'CVEID':res['CVEID'], 'Context':res['Context'], 'Method or Impact':res['ImpactMethod'],'OffensiveTechnique':res['result'][0][1]}
                if result not in listresult4:
                  listresult4.append(result)
                #res['OffensiveTechnique'] = res['result'][0][1]
            if res2['result'][0][0]>0.1:
              #else:
                #matching = [s for s in offens if res2['result'][0][1] in s]
                #print(matching)
                result={'CVEID':res2['CVEID'], 'Context':res2['Context'], 'Method or Impact':res2['LogicalImpact'],'OffensiveTechnique':res2['result'][0][1]}
                if result not in listresult4:
                  listresult4.append(result)
                #res['OffensiveTechnique'] = res2['result'][0][1]
      listresult6=[]
      for e in range(len(listresult4)):
        if listresult4[e]["CVEID"]==listresult4[e-1]["CVEID"] and listresult4[e]["OffensiveTechnique"]==listresult4[e-1]["OffensiveTechnique"]:
          listresult6.append(listresult4[e])
        """if e not in listresult3:
          cve=e["CVEID"]
          listresult3.append(e)"""
      if len(listresult4)!=1:
        listresultfinal = [i for i in listresult4 if i not in listresult6]
      else:
        listresultfinal=listresult6


      print(listresultfinal)
      for r in range(len(listresultfinal)):
        artifacts=[]
        technique=str(listresultfinal[r]['OffensiveTechnique'])
        art=searchar(technique)
        if len(art)>0:
          for a in art:
            if a=='Digital Artifact' and len(art)==1:
              artifactss=searchard(a)
              modelart = gensim.models.Word2Vec.load("/var/www/html/ADG/word2vecart.model")
              sentences_similarity3 = np.zeros(len(artifactss))
              for idx, sentence in enumerate(artifactss):
                context=listresultfinal[r]['Context']
                sentence_words3 = sentence.split()
                for word in sentence_words3:
                  sim_to_sentence3 = 0
                  if type(context)==str:
                    for target in context.split():
                        try:
                            sim_to_sentence3 += modelart.wv.similarity(word, target)
                        except KeyError:
                            pass # ignore words that aren't in vocabulary
                    sim_to_sentence3 /= len(sentence_words3)
                sentences_similarity3[idx] += sim_to_sentence3
                if type(context)==str:
                  if len(set(sentence_words3).intersection(context.split()))>=len(context.split())-1:
                    sentences_similarity3[idx]=sentences_similarity3[idx]+0.5
              result3 = list(zip(sentences_similarity3, artifactss))
              for z in result3:
                if type(context)==str:
                  intersec=set(z[1].split()).intersection(context.split())
              result3=heapq.nlargest(5, result3, key=lambda x:x[0])
              artifacts.append(result3[0][1])
            else:
              if a!='Digital Artifact':
                artifacts.append(a)
        else:
          artifactss=searchard('Digital Artifact')
          modelart = gensim.models.Word2Vec.load("/var/www/html/ADG/word2vecart.model")
          sentences_similarity3 = np.zeros(len(artifactss))
          for idx, sentence in enumerate(artifactss):
            context=listresultfinal[r]['Context']
            sentence_words3 = sentence.split()
            for word in sentence_words3:
              sim_to_sentence3 = 0
              #print(context)
              if type(context)==str:
                for target in context.split():
                    try:
                        sim_to_sentence3 += modelart.wv.similarity(word, target)
                    except KeyError:
                        pass # ignore words that aren't in vocabulary
                sim_to_sentence3 /= len(sentence_words3)
              sentences_similarity3[idx] += sim_to_sentence3
            if type(context)==str:
              if len(set(sentence_words3).intersection(context.split()))>=len(context.split())-1:
                sentences_similarity3[idx]=sentences_similarity3[idx]+0.5
          result3 = list(zip(sentences_similarity3, artifactss))
          for z in result3:
            if type(context)==str:
              intersec=set(z[1].split()).intersection(context.split())
          result3=heapq.nlargest(5, result3, key=lambda x:x[0])
          artifacts.append(result3[0][1])
        listresultfinal[r]['Artifact'] = artifacts
      modelart = gensim.models.Word2Vec.load("/var/www/html/ADG/word2vecart.model")
      for vul in range(len(listresultfinal)):
        sentences_similarity3 = np.zeros(len(listresultfinal[vul]['Artifact']))
        for idx, sentence in enumerate(listresultfinal[vul]['Artifact']):
          #print(sentences_similarity,sentence)
          context=listresultfinal[vul]['Context']
          #print(impact)
          #print(context,idx,sentence)
          sentence_words3 = sentence.split()
          #print(sentence_words)
          for word in sentence_words3:
            sim_to_sentence3 = 0
            #print(context)
            if type(context)==str:
              for target in context.split():
                  #print(idx,target,word)
                  if type(target)!=float:
                    try:
                        sim_to_sentence3 += modelart.wv.similarity(word, target)
                    except KeyError:
                        pass # ignore words that aren't in vocabulary
              sim_to_sentence3 /= len(sentence_words3)
          sentences_similarity3[idx] += sim_to_sentence3
        result3 = list(zip(sentences_similarity3, listresultfinal[vul]['Artifact']))
        #result3=heapq.nlargest(1, result3, key=lambda x:x[0])

      #Nouvelle approche
      removeart=[]
      removecounter=[]
      datasetcounter=[]
      countermeasure=[]
      propriete=[]
      phase=""
      category=""
      eradicationverb=["http://d3fend.mitre.org/ontologies/d3fend.owl#deletes","http://d3fend.mitre.org/ontologies/d3fend.owl#evicts","http://d3fend.mitre.org/ontologies/d3fend.owl#terminates","http://d3fend.mitre.org/ontologies/d3fend.owl#may-evict"]
      #identificationverb=["http://d3fend.mitre.org/ontologies/d3fend.owl#monitors","http://d3fend.mitre.org/ontologies/d3fend.owl#detects","http://d3fend.mitre.org/ontologies/d3fend.owl#analyzes", "http://d3fend.mitre.org/ontologies/d3fend.owl#verifies", "http://d3fend.mitre.org/ontologies/d3fend.owl#identifies", "http://d3fend.mitre.org/ontologies/d3fend.owl#evaluates"]
      identificationverb=["http://d3fend.mitre.org/ontologies/d3fend.owl#evaluates","http://d3fend.mitre.org/ontologies/d3fend.owl#validates","http://d3fend.mitre.org/ontologies/d3fend.owl#monitors","http://d3fend.mitre.org/ontologies/d3fend.owl#detects","http://d3fend.mitre.org/ontologies/d3fend.owl#neutralizes", "http://d3fend.mitre.org/ontologies/d3fend.owl#verifies","http://d3fend.mitre.org/ontologies/d3fend.owl#analyzes","http://d3fend.mitre.org/ontologies/d3fend.owl#restricts","http://d3fend.mitre.org/ontologies/d3fend.owl#spoofs","http://d3fend.mitre.org/ontologies/d3fend.owl#deceives-with"]
      containmentverb=["http://d3fend.mitre.org/ontologies/d3fend.owl#updates","http://d3fend.mitre.org/ontologies/d3fend.owl#suspends","http://d3fend.mitre.org/ontologies/d3fend.owl#may-contain","http://d3fend.mitre.org/ontologies/d3fend.owl#use-limits","http://d3fend.mitre.org/ontologies/d3fend.owl#obfuscates","http://d3fend.mitre.org/ontologies/d3fend.owl#disables","http://d3fend.mitre.org/ontologies/d3fend.owl#may-disable","http://d3fend.mitre.org/ontologies/d3fend.owl#use-limits","http://d3fend.mitre.org/ontologies/d3fend.owl#encrypts","http://d3fend.mitre.org/ontologies/d3fend.owl#limits","http://d3fend.mitre.org/ontologies/d3fend.owl#authenticates","http://d3fend.mitre.org/ontologies/d3fend.owl#filters","http://d3fend.mitre.org/ontologies/d3fend.owl#isolates","http://d3fend.mitre.org/ontologies/d3fend.owl#hardens","http://d3fend.mitre.org/ontologies/d3fend.owl#blocks"]
      #containmentverb=["http://d3fend.mitre.org/ontologies/d3fend.owl#validates","http://d3fend.mitre.org/ontologies/d3fend.owl#may-contain","http://d3fend.mitre.org/ontologies/d3fend.owl#use-limits","http://d3fend.mitre.org/ontologies/d3fend.owl#encrypts","http://d3fend.mitre.org/ontologies/d3fend.owl#restricts","http://d3fend.mitre.org/ontologies/d3fend.owl#limits""http://d3fend.mitre.org/ontologies/d3fend.owl#authenticates","http://d3fend.mitre.org/ontologies/d3fend.owl#filters","http://d3fend.mitre.org/ontologies/d3fend.owl#isolates","http://d3fend.mitre.org/ontologies/d3fend.owl#hardens","http://d3fend.mitre.org/ontologies/d3fend.owl#blocks","http://d3fend.mitre.org/ontologies/d3fend.owl#spoofs","http://d3fend.mitre.org/ontologies/d3fend.owl#deceives-with"]
      recoveryverb=["http://d3fend.mitre.org/ontologies/d3fend.owl#strengthens","http://d3fend.mitre.org/ontologies/d3fend.owl#enables","http://d3fend.mitre.org/ontologies/d3fend.owl#regenerates","http://d3fend.mitre.org/ontologies/d3fend.owl#restores"]
      preparationverb=["http://d3fend.mitre.org/ontologies/d3fend.owl#may-access","http://d3fend.mitre.org/ontologies/d3fend.owl#manages"]
      for result in listresultfinal:
          print(result)
          for res in result['Artifact']:
              request=search(res.replace(" ", ""))
              countermeasure=[i for n, i in enumerate(request[0]) if i not in request[0][:n]]
              propriete=[i for n, i in enumerate(request[1]) if i not in request[1][:n]]
              #print(res,len(propriete),len(countermeasure))
              for count in range(len(countermeasure)):
                  if res.find("File") >= 0 or res.find("Script") >= 0:
                      category="File"
                  else:
                    if res.find("Process") >= 0:
                      category="Process"
                    else:
                      if res.find("Email") >= 0:
                        category="Email"
                      else:
                        if res.find("Network") >= 0 or res.find("Address") >= 0 or res.find("IP") >= 0 or res.find("Domain") >= 0 or res.find("URL") >= 0 or res.find("Domain") >= 0 or res.find("Log") >= 0:
                          category="Network"
                        else:
                          if res.find("User") >= 0 or res.find("Token") >= 0 or res.find("Credential") >= 0 or res.find("Session") >= 0:
                            category="Identity"
                          else:
                            if res.find("Service") >= 0 or res.find("Key") >= 0:
                              category="Configuration"
                            else:
                              category="General"
                  #print(res,index)
                  #print(vdo.search_one(iri = "*"+result["CVEID"].split("#")[1]).hasIdentity[0].value[0])
                  
                  ontos = World()
                  ontos.get_ontology("/var/www/html/ADG/rdfxmlgraph.owl").load() #path to the owl file is given here
                  #sync_reasoner(my_world)  #reasoner is started and synchronized here
                  g = ontos.as_rdflib_graph()
                  cveid=cveiddata(g,result["CVEID"])[0]
                  if propriete[count].split(',')[1] in eradicationverb:
                    phase="Eradication"
                    datasetcounter.append({'CVEID':cveid, 'Method or Impact':result['Method or Impact'], 'Context':result['Context'], 'Artifact':res, 'Countermeasure':countermeasure[count], 'Phase':phase, 'Category':category})
                    phase=""
                  else:
                    if propriete[count].split(',')[1] in identificationverb:
                      phase="Identification"
                      #cveid=vdo.search_one(iri = "*"+result["CVEID"].split("#")[1]).hasIdentity[0].value[0]
                      datasetcounter.append({'CVEID':cveid, 'Method or Impact':result['Method or Impact'], 'Context':result['Context'], 'Context':result['Context'], 'Artifact':res, 'Countermeasure':countermeasure[count], 'Phase':phase, 'Category':category})
                      phase=""
                    else:
                      if propriete[count].split(',')[1] in containmentverb:
                        phase="Containment"
                        #cveid=vdo.search_one(iri = "*"+result["CVEID"].split("#")[1]).hasIdentity[0].value[0]
                        datasetcounter.append({'CVEID':cveid, 'Method or Impact':result['Method or Impact'], 'Context':result['Context'], 'Context':result['Context'], 'Artifact':res, 'Countermeasure':countermeasure[count], 'Phase':phase, 'Category':category})
                        phase=""
                      else:
                        if propriete[count].split(',')[1] in recoveryverb:
                          phase="Recovery"
                          #cveid=vdo.search_one(iri = "*"+result["CVEID"].split("#")[1]).hasIdentity[0].value[0]
                          datasetcounter.append({'CVEID':cveid, 'Method or Impact':result['Method or Impact'], 'Context':result['Context'], 'Context':result['Context'], 'Artifact':res, 'Countermeasure':countermeasure[count], 'Phase':phase, 'Category':category})
                          phase=""
                        else:
                          if propriete[count].split(',')[1] in preparationverb:
                            phase="Preparation"
                            #cveid=vdo.search_one(iri = "*"+result["CVEID"].split("#")[1]).hasIdentity[0].value[0]
                            datasetcounter.append({'CVEID':cveid, 'Method or Impact':result['Method or Impact'], 'Context':result['Context'], 'Context':result['Context'], 'Artifact':res, 'Countermeasure':countermeasure[count], 'Phase':phase, 'Category':category})
                            phase=""
      #output
      #Nouvelle approche
      if len(datasetcounter)!=0:
        tsv_file = open("/var/www/html/ADG/countermeasureexec.tsv", "w")
        tsv_writer = csv.writer(tsv_file, delimiter='\t')
        print(datasetcounter)
        tsv_writer.writerow(datasetcounter[0].keys()) # write the header

        for row in datasetcounter: # write data rows
            tsv_writer.writerow(row.values())

        tsv_file.close()
        # Convert JSON objects to a list of lists
        data_to_write = [
            [item["CVEID"], str(item["Method or Impact"]), item["Context"], item["Artifact"], item["Countermeasure"], item["Phase"], item["Category"]] for item in datasetcounter
        ]

        # File path to the existing TSV file
        file_path = '/var/www/html/ADG/res7.tsv'

        # Open the file in append mode
        with open(file_path, 'a', newline='') as file:
            writer = csv.writer(file, delimiter='\t')
            writer.writerows(data_to_write)