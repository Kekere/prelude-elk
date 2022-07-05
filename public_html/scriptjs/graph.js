function updateGraph(){
  graph = JSON.parse(localStorage.getItem('myjson'))
  //console.log(graph)
  var val=0;
  var idvul=0;
  var cve='';
  var product="";
  var address=document.getElementById("your-hidden-address").value;
  var protocol=document.getElementById("your-hidden-protocol").value;
  var port=document.getElementById("your-hidden-port").value;
  var severity=document.getElementById("your-hidden-severity").value;
  var addresssource=document.getElementById("your-hidden-addresssource").value;
  var protocolsource=document.getElementById("your-hidden-protocolsource").value;
  var portsource=document.getElementById("your-hidden-portsource").value;
  var timestamp=document.getElementById("your-hidden-timestamp").value;
  var username='';
  var kafkajson;
  var arrayip=[];
  var arraycve=[];
  var arrayid=[];
  //var severitysource=document.getElementById("your-hidden-severitysource").value;
  //console.log(document.getElementById("your-hidden-jsonobj").value)
  
  var jsonfiles=document.getElementById("your-hidden-jsonlist").value.split(',');
  //arraynodes=graph["nodes"];
  arraynodes=graph["nodes"];
  for(var ncve=0; ncve<arraynodes.length; ncve++){
    if(arraynodes[ncve]["label"].indexOf("vulExists")==0){
      var id=arraynodes[ncve]["id"];
      var valip=arraynodes[ncve]["label"].split(",")[0].split("'")[1];
      var valcve=arraynodes[ncve]["label"].split(",")[1].split("'")[1];
      arrayid.push(id);
      arrayip.push(valip);
      console.log(valcve);
      arraycve.push(valcve);
    }
    
  }
  console.log(arraycve);
  console.log(arrayip);
  for (var i = 0; i < graph["nodes"].length; i++){
  var hacl=graph["nodes"][i]["label"].indexOf("hacl");
  var net=graph["nodes"][i]["label"].indexOf("networkServiceInfo");
  var vul=graph["nodes"][i]["label"].indexOf("vulExists");
  var ch;
  
 
  if(severity=="high" || severity=="medium" || severity=="low"){
    if(hacl==0){
      var sep=graph["nodes"][i]["label"].split(',');
      adds=sep[0].split("'")[1];
     
      if(adds==addresssource && sep[2]==protocol && parseInt(sep[3].split("):")[0])==parseInt(port)){
        ch=1
        
      }
      
    }
    if(net==0){
      var sep=graph["nodes"][i]["label"].split(',');
      add=sep[0].split("'")[1];
      addsource=sep[0].split("'")[1];
      
      if(add==address && sep[2]==protocol && parseInt(sep[3].split("):")[0])==parseInt(port)){
        val=1;
        
  
        
        product=sep[1].split("'")[0];
        username=sep[4].split(")")[0];
        
        
      }
      else{
        if(ch==1){
          product=sep[1].split("'")[0];
          
          val=1;
          
        }
        else{
          if(ch==1){
            product=sep[1].split("'")[0];
           
          }
          
        }
      }
      
    }
    else{

    }
  }
  
  if(vul==0 && val==1){

      var sep=graph["nodes"][i]["label"].split(',');
      idvul=graph["nodes"][i]["id"];
   
      if(sep[0].split("(")[1].split("'")[1]==address){
        cve=sep[1].split("'")[1];
        impact=sep[4].split(")")[0]
        val=0;
        valprod=0;
        var prod="";
        var arraylinks=[];
        var arraynodes=[];
        var newlinkr={};
        var newnoder={};
        var newlinka={};
        var newnodea={};
        var onto="vdo/"+cve+"json";
        var seps=impact.split(/(?=[A-Z])/);
        var precondition='';
        var products=[];
        var newcve='';
        var user='';
        var mean='';
        var newimpact='';
        var donnees={};
        var arraydonnees=[];
        var arrayremovenodes=[];
        var arraykafka=[];
        var lengthdonnee=[];
        var issource=0;
        var countpostcondition=0;
        var jsonpost={};
        var privilegesneeded='';
        var gainedPrivileges='';
        var prod1="";
        
        
        var name=localStorage.getItem('someVarKey');
        
        if(localStorage.getItem('someVarKey')=='null'){
          //Find index of specific object using findIndex method.    
          objIndex = graph["nodes"].findIndex((obj => obj.id == idvul));

          //Log object to Console.
          //console.log("Before update: ", graph["nodes"][objIndex]);
          issource=graph["links"].findIndex(obj => obj.source == idvul);
          
          //Update object's name property.
          graph["nodes"][objIndex].group = 6;
          
          
          $.getJSON("../countermeasurelist.json",function(datacounte){
            for(var r=0; r<datacounte["counter"].length; r++){
              ct=datacounte["counter"][r]["cve"];
              if(ct==cve){
                localStorage.setItem("cr",datacounte["counter"][r]["countermeasure"]);
               
              }
            }
          });
       
          kafkajson={"Header": {
              "Source": "CTM",      
              "Timestamp": timestamp,      
              "Criticality": severity,      
              "Description": "CTM / Cyber Vulnerability"
          },      
          "Payload": {      
              "CVEID": cve,      
              "IP address": address,      
              "Product": product,      
              "User Name": username,      
              "Countermeasure": localStorage.getItem("cr")
        }
        }
        arraykafka.push(kafkajson);
        //localStorage.setItem('alerte',JSON.stringify(kafkajson,null,4));
        localStorage.setItem('alerte',JSON.stringify(arraykafka,null,4));
        localStorage.setItem('sendalert',1);
        
                                     
        }
        else{
          localStorage.setItem('sendalert',2);
        }
        
        if(issource!=-1){
          $.getJSON("./vdo/"+cve+".json", function(json) {
          
            if(json["Vulnerability"]["hasIdentity"][0]["value"]==cve && localStorage.getItem('someVarKey')!=cve){
             
              
              for(var e=0; e<json["Vulnerability"]["hasScenario"].length; e++){
                for(var b=0; b<json["Vulnerability"]["hasScenario"][e]["affectsProduct"]["hasEnumeration"]["values"].length; b++){
                  prod=json["Vulnerability"]["hasScenario"][e]["affectsProduct"]["hasEnumeration"]["values"][b].split(':')[4];
                  if(prod==product){
                    valprod=1;
                    if(localStorage.getItem('sendalert')=='1'){
               
                      const alertes =  localStorage.getItem("alerte");
                      const jsonString = alertes;
                      
                      
                           $.ajax
                            ({
                                type: "GET",
                                dataType : 'json',
                                async: false,
                                url: '../scriptphp/savejson.php',
                                data: { data: jsonString},
                                success: function () {},
                                failure: function() {alert("Error!");}
                            })
                            $.ajax
                              ({
                                  type: "POST",
                                  dataType : 'json',
                                  global: false,
                                  async:false,
                                  url: './scriptphp/executeproducer.php',
                                  success: function () {alert("Thanks!"); },
                                  failure: function() {alert("Error!");}
                              });
                              localStorage.setItem('sendalert','2') 
                    }
                    
                    arraykafka=[];
                  }
                }
                
                for(var o=0; o<json["Vulnerability"]["hasScenario"][e]["hasAction"].length; o++){
                  
                  if(json["Vulnerability"]["hasScenario"][e]["hasAction"][o]["resultsInImpact"].length==1){
                    for(var t=0; t<json["Vulnerability"]["hasScenario"][e]["hasAction"][o]["resultsInImpact"].length; t++){
                      if(o==1){
                        
                        check=json["Vulnerability"]["hasScenario"][e]["hasAction"][o]["resultsInImpact"][t]["hasLogicalImpact"]
    
                        var isEvery = seps.every(item => check.toLowerCase().includes(item.toLowerCase()));
                        
                        
                        if(isEvery==true && valprod!=0){
                          logicalimpact=json["Vulnerability"]["hasScenario"][e]["hasAction"][1]["resultsInImpact"][t]["hasLogicalImpact"].split("::").slice(-1)[0];
                          privilegesgained=json["Vulnerability"]["hasScenario"][e]["hasAction"][1]["resultsInImpact"][t]["gainedPrivileges"]

                          arraylinks=graph["links"];
                          arraynodes=graph["nodes"];
                                                   
                          for(var p=0; p<arraylinks.length; p++){
                            if(idvul==arraylinks[p]["source"]){
                              for(var m=0; m<arraylinks.length; m++){
                                if(arraylinks[p]["target"]==arraylinks[m]["source"]){
                                  
                                  
                                  newtarget=parseInt(arraynodes.length+1)
                                  newlinkr={"source":parseInt(arraylinks[m]["target"]),"target":newtarget};
                                  newtargeta=parseInt(newtarget+1)
                                  newlinka={"source":newtarget,"target":newtargeta};
                                  newnoder={id: newtarget, group: 2, label: "RULE "+newtarget+" ("+logicalimpact+"):0"}
                                  newnodea={id: newtargeta, group: 1, label: logicalimpact+"('"+address+"'):0"}
                                  arraylinks.push(newlinkr);
                                  arraylinks.push(newlinka);
                                  arraynodes.push(newnoder);
                                  arraynodes.push(newnodea);
                                  //console.log(arraynodes);
                                  
                                  var weaknesses=json["Vulnerability"]["hasScenario"][e]["hasExploitedWeakness"];
                                  if(logicalimpact=="Panic" || logicalimpact=="Reboot"){
                                    for(var z=0; z<arraynodes.length; z++){
                                      if(arraynodes[z]["label"].indexOf("physicalDamage")==0){
                                        newlinkr={"source":newtargeta,"target":arraynodes[z-1]["id"]};
                                        arraylinks.push(newlinkr);
                                      } 
                                    }
                                    
                                  }
                                
                                  for(var y=0; y<jsonfiles.length; y++){
                                    
                                    
                                    
                                    var n=jsonfiles[y];
                                    //console.log(n.split(".json")[0]);
                                    $.getJSON("./vdo/"+n, function(donnee){
                                      
                                      console.log(donnee["Vulnerability"]["hasScenario"][0]["barrier"]);
                                      //precondition=donnee["Vulnerability"]["hasScenario"][0]["barrier"][0]["barrierType"].split(':')[4];
                                      newcve=donnee["Vulnerability"]["hasIdentity"][0]["value"];
                                      console.log(donnee["Vulnerability"]["hasScenario"][0]["barrier"][0]);
                                      privilegesneeded=donnee["Vulnerability"]["hasScenario"][0]["barrier"][0]["neededPrivileges"]
                                      
                                      var caction;
                                      var cprivileges;
                                      var casset;
  
                                      for(var u=0; u<donnee["Vulnerability"]["hasScenario"].length; u++){
                                        for(var h=0; h<donnee["Vulnerability"]["hasScenario"][u]["affectsProduct"]["hasEnumeration"]["values"].length; h++){
                                          prod1=donnee["Vulnerability"]["hasScenario"][u]["affectsProduct"]["hasEnumeration"]["values"][h].split(':')[4];
                                          products.push(prod1);
                                                                                 
                                        }
                                        if(donnee["Vulnerability"]["hasScenario"][u]["requiresAttackTheatre"]=="Internet"){
                                          mean="remoteExploit";
                                        }
                                        user=donnee["Vulnerability"]["hasScenario"][u]["barrier"][0]["neededPrivileges"];
                                        newimpact=donnee["Vulnerability"]["hasScenario"][u]["hasAction"][1]["resultsInImpact"][0]["hasLogicalImpact"].split('::')[1];
                                        caction=donnee["Vulnerability"]["hasScenario"][u]["barrier"][0]["blockedByBarrier"];
                                        cprivileges=donnee["Vulnerability"]["hasScenario"][u]["barrier"][0]["neededPrivileges"];
                                        casset=donnee["Vulnerability"]["hasScenario"][u]["barrier"][0]["relatesToContext"];
                                        
                                        
                                      }
                                      //donnees={"cve":newcve,"user":user,"newimpact":newimpact,"caction":caction,"cprivileges":cprivileges,"casset":casset,"products":products,"mean":mean,"precondition":precondition}
                                      donnees={"cve":newcve,"user":user,"newimpact":newimpact,"caction":caction,"cprivileges":cprivileges,"casset":casset,"products":products,"mean":mean}
                                      products=[];
                                      arraydonnees.push(donnees);
                                      
                                      localStorage.setItem('arraydonnees',JSON.stringify(arraydonnees,null,4));                     
                                    })
                                                
                                  
                                  }
                                  lengthdonnee=JSON.parse(localStorage.getItem('arraydonnees'));
                                  console.log(JSON.parse(localStorage.getItem('arraydonnees')).length);
                                  
                                  for(z=0; z<lengthdonnee.length; z++){
                                    console.log(arraycve,lengthdonnee[z]["cve"]);
                                    console.log(product,lengthdonnee[z]["products"])
                                    //if(weaknesses.includes(lengthdonnee[z]["precondition"]) && lengthdonnee[z]["products"].includes(product)){
                                      if(privilegesgained==lengthdonnee[z]["cprivileges"] && lengthdonnee[z]["products"].includes(product)){
                                        
                                      if(!arrayremovenodes.includes(lengthdonnee[z]["cve"])){
                                        arrayremovenodes.push(lengthdonnee[z]["cve"]);
                                        countpostcondition=countpostcondition+1;
                                        if(arraycve.includes(lengthdonnee[z]["cve"])){
                                          
                                          var position=arraycve.findIndex(obj => obj ==lengthdonnee[z]["cve"]);
                                          newtarget=arrayid[position];
                                          console.log(newtargeta,newtarget);
                                          newlinkr={"source":newtargeta,"target":newtarget};
                                          arraylinks.push(newlinkr);
                                          console.log(arraylinks);
                                        }
                                        else{
                                          
                                          newtarget=parseInt(arraynodes.length+1)
                                          newlinkr={"source":newtargeta,"target":newtarget};
                                          
                                          newnoder={id: newtarget, group: 4, label: "vulExists"+"('"+address+"',"+"'"+lengthdonnee[z]["cve"]+"'"+","+product+","+lengthdonnee[z]["mean"]+","+lengthdonnee[z]["newimpact"]+"):0"}
                                          
                                          arraylinks.push(newlinkr);
                                          arraynodes.push(newnoder);
                                        }
                                        
                                        localStorage.setItem('counter','remove '+lengthdonnee[z]["caction"]+' from '+lengthdonnee[z]["cprivileges"]+' on ' + lengthdonnee[z]["casset"]);
                                        localStorage.setItem('newcve',lengthdonnee[z]["cve"]);
                                        
                                        kafkajson={"Header": {
                                          "Source": "CTM",      
                                          "Timestamp": timestamp,      
                                          "Criticality": severity,      
                                          "Description": "CTM / Cyber Vulnerability"
                                        },      
                                        "Payload": {      
                                            "CVEID": localStorage.getItem('newcve'),      
                                            "IP address": address,      
                                            "Product": product,      
                                            "User Name": username,      
                                            "Countermeasure": localStorage.getItem('counter')
                                        }
                                        }
                                        //console.log(arraykafka);
                                        arraykafka.push(kafkajson);
                                        
                                        console.log(lengthdonnee.length,arraykafka.length,countpostcondition);
                                        //if(lengthdonnee.length==arraykafka.length){
                                       if(countpostcondition==arraykafka.length){
                                          localStorage.setItem('alerte',JSON.stringify(arraykafka,null,4));
                                          console.log(localStorage.getItem('alerte'));
                                          const alertes =  localStorage.getItem("alerte");
                                          const jsonString = alertes;
                                              $.ajax
                                              ({
                                                  type: "GET",
                                                  dataType : 'json',
                                                  async: false,
                                                  url: '../scriptphp/savejson.php',
                                                  data: { data: jsonString},
                                                  success: function () {},
                                                  failure: function() {alert("Error!");}
                                              })
                                              $.ajax
                                              ({
                                                  type: "POST",
                                                  dataType : 'json',
                                                  global: false,
                                                  async:false,
                                                  url: './scriptphp/executeproducer.php',
                                                  success: function () {alert("Thanks!"); },
                                                  failure: function() {alert("Error!");}
                                              });
                                        }
                                        /*for(var z=0; z<arraynodes.length; z++){
                                          if(arraynodes[z]["label"].indexOf('networkServiceInfo')==0){
                                            //console.log(address,arraynodes[z]["label"].split("(")[1].split(",")[0].split("'")[1])
                                            if((arraynodes[z]["label"].split("(")[1].split(",")[0].split("'")[1])==address && arraynodes[z]["label"].split("(")[1].split(",")[1]==product){
                                              //console.log(arraynodes[z]["label"].split("(")[1].split(",")[1])
                                              //console.log(arraynodes[z]["id"],newtarget);
                                              //newlinka={"source":newtargeta,"target":newtarget};
                                              newlinkr={"source":arraynodes[z]["id"],"target":newtarget};
                                              //newnodea={id: newtarget, group: 4, label: "vulExists"+"('"+address+"',"+"'"+lengthdonnee[z]["cve"]+"'"+","+product+","+lengthdonnee[z]["mean"]+","+lengthdonnee[z]["newimpact"]+"):0"}
                                              arraylinks.push(newlinkr);
                                            }
                                          }
  
                                        }*/
                                            
                                      
                                      }
                                      
                                    }
                                  
                                    
                                    newnoder={};
                                    newlinkr={};
                                    newnodea={};
                                    newlinka={};
                                    jsonfinal={"nodes":arraynodes,"links":arraylinks};
                                    //if(arraykafka.length==arraydonnees.length){
                                      //console.log(arraykafka);
                                      //console.log(lengthdonnee);
                                      //console.log(arraykafka.length,arraydonnees.length,arrayremovenodes.length);
                                    //}
                                    
                                    localStorage.setItem('myjson',JSON.stringify(jsonfinal,null,4));
                                    obj=JSON.parse(localStorage.getItem('myjson')); 
                                   
                                  }
                                  
                                }
                              }
                              
                            }
                          }
                        }  
                      }
                                              
                    }
                    //arraykafka=[];
                    /*newnoder={};
                    newlinkr={};
                    newnodea={};
                    newlinka={};
                    jsonfinal={"nodes":arraynodes,"links":arraylinks};
                    //console.log(arraykafka);
                    localStorage.setItem('myjson',JSON.stringify(jsonfinal,null,4));
                    obj=JSON.parse(localStorage.getItem('myjson')); */
                   
                  }
                  
                  else{
                    
                    for(var r=0; r<json["Vulnerability"]["hasScenario"][e]["hasAction"][o]["resultsInImpact"].length; r++){
                      check=json["Vulnerability"]["hasScenario"][e]["hasAction"][o]["resultsInImpact"][r]["hasLogicalImpact"]
                      var isEvery = seps.every(item => check.toLowerCase().includes(item.toLowerCase()));
                      if(isEvery==true && valprod!=0){
                        logicalimpact=json["Vulnerability"]["hasScenario"][e]["hasAction"][o]["resultsInImpact"][r]["hasLogicalImpact"].split("::").slice(-1)[0];
                        
                        arraylinks=graph["links"];
                        
                        for(var p=0; p<arraylinks.length; p++){
                          if(idvul==arraylinks[p]["source"]){
                            for(var m=0; m<arraylinks.length; m++){
                              if(arraylinks[p]["target"]==arraylinks[m]["source"]){
                                
                                arraynodes=graph["nodes"];
                                newtarget=parseInt(arraynodes.length+1)
                                newlinkr={"source":parseInt(arraylinks[m]["target"]),"target":newtarget};
                                newtargeta=parseInt(newtarget+1)
                                newlinka={"source":newtarget,"target":newtargeta};
                                newnoder={id: newtarget, group: 2, label: "RULE "+newtarget+" ("+logicalimpact+"):0"}
                                newnodea={id: newtargeta, group: 1, label: logicalimpact+"('"+address+"'):0"}
                                arraylinks.push(newlinkr);
                                arraylinks.push(newlinka);
                                arraynodes.push(newnoder);
                                arraynodes.push(newnodea);
                                if(logicalimpact=="Panic" || logicalimpact=="Reboot"){
                                  for(var z=0; z<arraynodes.length; z++){
                                    if(arraynodes[z]["label"].indexOf("physicalDamage")==0){
                                      newlinkr={"source":newtargeta,"target":arraynodes[z-1]["id"]};
                                      arraylinks.push(newlinkr);
                                    } 
                                  }
                                  
                                }
                              }
                            }
                            
                          }
                        }
                      }
                      
                    }
                    newnoder={};
                    newlinkr={};
                    newnodea={};
                    newlinka={};
                    jsonfinal={"nodes":arraynodes,"links":arraylinks};
                  
                    localStorage.setItem('myjson',JSON.stringify(jsonfinal,null,4));
                    obj=JSON.parse(localStorage.getItem('myjson')); 
                  
                    
                  }
                }
              }
              localStorage.setItem("someVarKey", cve);
            }
          });
        }
        else{
          //create rule based on logical impact of cve and network service info
          //create node for rule
          //create links from vulExists to rule node and fro NetworkServiceInfo to rule
        }
        
      }
  } 
  }
  d3.select("g").remove()
  generateGraph("./mulval_generated_json.json");
}

document.getElementById("home").onclick = function() {
  localStorage.setItem('sendalert',2);
  localStorage.setItem("someVarKey",null);
  var link = document.getElementById("home");
  link.setAttribute("href", "./index.html");
  return true;
}
var button = document.getElementById( 'download' );
button.addEventListener( 'click', function() {
    obj=JSON.parse(localStorage.getItem('myjson'));
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([JSON.stringify(obj, null, 4)], {
      type: "text/plain"
    }));
    a.setAttribute("download", "data.json");
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);

});
