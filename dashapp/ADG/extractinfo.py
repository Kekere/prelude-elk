import requests
from bs4 import BeautifulSoup
import re
from nltk.tokenize import word_tokenize
import nltk
import numpy as np
nltk.download('punkt')

def extractcve(cveid):
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

  else:
      print(f"Failed to retrieve data. Status code: {response.status_code}")
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
  print(attackposition)
  
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
  software_noun=np.array(["keycloak","openfind","tracker","wordpress","cloud","zimbra","teclib","zebra","soft","unity","word","webex","excel","explorer","office","apache","acrobat","control","modicon","bank","financial","symantec","s-cms","ibm","adobe","realnetworks","trend micro","hp","blue coat","samba","ca","apache","firefox","antivirus","application","smart","app","freeware","sap","mobile","vbscript","digital","client","mcafee","cardio"])
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
  owl_file_path='rdfxmlgraph.owl'
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
    #actiondata='<!-- http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Action'+cve_id+ '-->\n<owl:NamedIndividual rdf:about="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Action'+cve_id+ '">\n<rdf:type rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Action"/>\n<untitled-ontology-4:affectsContext rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#'+context+'"/>\n<untitled-ontology-4:hasImpactMethod rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#'+impactmethod+'"/>\n<untitled-ontology-4:resultsInImpact rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Impact1"/>\n<untitled-ontology-4:resultsInImpact rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Impact2"/>\n<untitled-ontology-4:resultsInImpact rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Impact3"/>\n<untitled-ontology-4:resultsInImpact rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Impact4"/>\n</owl:NamedIndividual>'
    
  #productenumdata=''
  #new_individual_tags=soupvdo.new_tag()


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

    #productenumdata='<!-- http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#ProdEnum'+cve_id+' -->\n<owl:NamedIndividual rdf:about="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#ProdEnum'+cve_id+'">\n<rdf:type rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#ProductEnumeration"/>\n<untitled-ontology-4:values rdf:datatype="http://www.w3.org/2001/XMLSchema#string">'+cpenewlist[-1]+'</untitled-ontology-4:values>\n<untitled-ontology-4:values rdf:datatype="http://www.w3.org/2001/XMLSchema#string">'+cpenewlist[0]+'</untitled-ontology-4:values>\n</owl:NamedIndividual>'
  #productdata=''
  #productdata='<!-- http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Product'+cve_id+' -->\n<owl:NamedIndividual rdf:about="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Product'+cve_id+'">\n<rdf:type rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Product"/>\n<untitled-ontology-4:hasProductEnumeration rdf:resource="http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#ProdEnum'+cve_id+'"/>\n</owl:NamedIndividual>'

  dict_attributes={"rdf:about":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Product"+cve_id}
  new_individual_tags = soupvdo.new_tag('owl:NamedIndividual', attrs=dict_attributes)
  new_individual_tags.append('\n')
  dict_attributes2={"rdf:resource":"http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#Product"}
  new_individual_tags.append(soupvdo.new_tag('rdf:type', attrs=dict_attributes2))
  new_individual_tags.append('\n')
  dict_attributes3 = {"rdf:resource" : "http://www.semanticweb.org/keren/ontologies/2022/6/untitled-ontology-4#ProdEnum"+cve_id}
  new_individual_tags.append(soupvdo.new_tag('untitled-ontology-4:hasProductEnumeration',attrs=dict_attributes3))
  new_individual_tags.append('\n')

  last_description_tag.insert_after("\n")
  last_description_tag.insert_after(new_individual_tagscve)
  last_description_tag.insert_after(new_individual_tagsid)
  last_description_tag.insert_after(new_individual_tags)
  last_description_tag.insert_after(new_individual_tagsenum)
  last_description_tag.insert_after(new_individual_tagsact)
  last_description_tag.insert_after(new_individual_tagsmet)


  #print(new_individual_tagsact)
  # Save the modified OWL file
  with open(owl_file_path, 'w') as file:
      file.write(str(soupvdo))
  #with open(cve_id+".txt", "a") as myfile:
  #    myfile.write(productenumdata+'\n'+productdata+'\n'+attackerdata+'\n'+actiondata+'\n'+iddata+'\n'+cvedata+'\n')