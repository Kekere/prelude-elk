function updateGraph(){
  graph = JSON.parse(localStorage.getItem('myjson'))
  //console.log(graph["links"].length);
  //console.log(graph["nodes"].length);
  var val=0;
  var idvul=0;
  var cve='';
  var product="";
  var address=document.getElementById("your-hidden-address").value;
  var protocol=document.getElementById("your-hidden-protocol").value;
  var port=document.getElementById("your-hidden-port").value;
  var severity=document.getElementById("your-hidden-severity").value;
  var addresssource=document.getElementById("your-hidden-addresssource").value;
  //var protocolsource=document.getElementById("your-hidden-protocolsource").value;
  //var portsource=document.getElementById("your-hidden-portsource").value;
  var timestamp=document.getElementById("your-hidden-timestamp").value;
  var username='';
  var kafkajson;
  var arrayip=[];
  var arraycve=[];
  var arrayid=[];
  var cveliste=[];
  //console.log(JSON.parse(localStorage.getItem("cveliste")));
  var jsonfiles=document.getElementById("your-hidden-jsonlist").value.split(',');
  arraynodes=graph["nodes"];
  for(var ncve=0; ncve<arraynodes.length; ncve++){
    if(arraynodes[ncve]["label"].indexOf("vulExists")==0){
      var id=arraynodes[ncve]["id"];
      var valip=arraynodes[ncve]["label"].split(",")[0].split("'")[1];
      var valcve=arraynodes[ncve]["label"].split(",")[1].split("'")[1];
      arrayid.push(id);
      arrayip.push(valip);
      arraycve.push(valcve);
    }
    
  }
  for (var i = 0; i < graph["nodes"].length; i++){
  var hacl=graph["nodes"][i]["label"].indexOf("hacl");
  var net=graph["nodes"][i]["label"].indexOf("networkServiceInfo");
  var acc=graph["nodes"][i]["label"].indexOf("hasAccount");
  var mal=graph["nodes"][i]["label"].indexOf("accessMaliciousInput");
  var ch;
    
  if(severity=="high" || severity=="medium" || severity=="low"){
    if(hacl==0){
      var sep=graph["nodes"][i]["label"].split(',');
      adds=sep[0].split("'")[1];
     
      if(adds==addresssource && sep[2]==protocol && parseInt(sep[3].split("):")[0])==parseInt(port)){
        ch=1
        
      }
      
    }
    //console.log(mal,net,acc, graph["nodes"][i]["label"]);
    if(net==0){
      //console.log(mal,net,acc, graph["nodes"][i]["id"]);
      var sep=graph["nodes"][i]["label"].split(',');
      add=sep[0].split("'")[1];
      addsource=sep[0].split("'")[1];
      //console.log(sep[1].split(" ")[0].replace("'",""));
      //console.log(add,sep[2],parseInt(sep[3].split("):")[0].split("'")[1]),parseInt(sep[3].split("):")[0]),parseInt(port));
      //console.log(sep[2]);
      if(sep[1]!="no_products" && add==address && sep[2]==protocol && parseInt(sep[3].split("):")[0].split("'")[1])==parseInt(port)){
        
  
        pros=sep[1];
        //console.log(sep);
        product=sep[1].split(" ")[0].replace("'","");
        //console.log(pros,product);
        username=sep[4].split(")")[0];
        //console.log(product);
        for (var i = 0; i < graph["nodes"].length; i++){
          
          var vul=graph["nodes"][i]["label"].indexOf("vulExists");
          
          if(vul==0){
            
            addvul=graph["nodes"][i]["label"].split(',')[0].split("'")[1];
            prodvul=graph["nodes"][i]["label"].split(',')[2];
            cve=graph["nodes"][i]["label"].split(",")[1].split("'")[1];
            impact=graph["nodes"][i]["label"].split(',')[4].split(")")[0];
            if(addvul==add && prodvul==pros){
              //console.log(prodvul,pros);
              //console.log(vul,cve);
              //console.log(graph["nodes"][i]["label"]);
              idvul=graph["nodes"][i]["id"];
              //console.log(cve,impact);
              val=1;
              val=0;
              valprod=0;
              var prod="";
              var prod2="";
              var arraylinks=[];
              var arraynodes=[];
              var newlinkr={};
              var newnoder={};
              var newlinka={};
              var newnodea={};
              var newlinkv={};
              var newnodev={};
              var onto="vdo/"+cve+"json";
              var seps=impact.split(/(?=[A-Z])/);
              var precondition='';
              var products=[];
              var newcve='';
              var user='';
              var mean='';
              var newimpact='';
              var impactmethod='';
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
              var lastcve='';
              
              
              var name=localStorage.getItem('someVarKey');

              if(localStorage.getItem('someVarKey')=="null" && cve!="CVE-XXXX-XXXX"){   

                objIndex = graph["nodes"].findIndex((obj => obj.id == idvul));
      
                graph["nodes"][objIndex].group = 6;
                $.ajax({
                  dataType: "json",
                  data:cve,
                  url: "../scriptphp/countermeasure.json",
                  dataType: "json",
                  async: false, 
                  success: function(data) {
                    countermeasure=data["counter"].findIndex((obj => obj.CVE == cve));
                    localStorage.setItem("cr",data["counter"][countermeasure]["Countermeasure"]);
                      kafkajson={
                        "Header": {
                        "Source": "CTM",      
                        "Timestamp": timestamp,      
                        "Criticality": "high",      
                        "Description": "CTM / Cyber Vulnerability"
                        },      
                        "Payload": {      
                        "CVEID": cve,      
                        "IP address": address,      
                        "Product": product,      
                        "User Name": username,      
                        "Countermeasure": localStorage.getItem("cr"),
                        "Status": "Exploited"
                        }
                      }
                      arraykafka.push(kafkajson);
                      localStorage.setItem('alerte',JSON.stringify(arraykafka,null,4));
                      localStorage.setItem('sendalert',1);
                      const alertes =  localStorage.getItem("alerte");
                      const jsonString = alertes;
                      var localcve=JSON.parse(localStorage.getItem("cveliste"));
                      if(!localcve.includes(cve)){
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
                          cveliste.push(cve);
                          localStorage.setItem("cveliste",JSON.stringify(cveliste));
                          //console.log(JSON.parse(localStorage.getItem("cveliste")));
                      }
                      listcve=JSON.parse(localStorage.getItem("cveliste"));
                      //console.log(listcve.length,cve);
                      $.getJSON("./vdo/"+cve+".json", function(json) {
                        //lastcve=json["Vulnerability"]["hasIdentity"][0]["value"];
                        //console.log(listcve.length,cve);
                        lastcve=cve;
                        //if(json["Vulnerability"]["hasIdentity"][0]["value"]==cve){
                          
                          
                          for(var e=0; e<json["Vulnerability"]["hasScenario"].length; e++){
                            for(var b=0; b<json["Vulnerability"]["hasScenario"][e]["affectsProduct"]["hasEnumeration"]["values"].length; b++){
                              prod=json["Vulnerability"]["hasScenario"][e]["affectsProduct"]["hasEnumeration"]["values"][b].split(':')[4];
                              prod2=json["Vulnerability"]["hasScenario"][e]["affectsProduct"]["hasEnumeration"]["values"][b].split(':')[3];
                              //console.log(prod.split('_')[0],prod2,product);
                              if(prod.split('_')[0]==product || prod2==product){
                                valprod=1;
                                
                              }
                            }
                            
                            for(var o=0; o<json["Vulnerability"]["hasScenario"][e]["hasAction"].length; o++){
                              //console.log(prod,prod2);
                              if(json["Vulnerability"]["hasScenario"][e]["hasAction"][o]["resultsInImpact"].length>=1){
                                for(var t=0; t<json["Vulnerability"]["hasScenario"][e]["hasAction"][o]["resultsInImpact"].length; t++){
                                  if(o==1){
                                    
                                    check=json["Vulnerability"]["hasScenario"][e]["hasAction"][o]["resultsInImpact"][t]["hasLogicalImpact"]
                
                                    var isEvery = seps.every(item => check.toLowerCase().includes(item.toLowerCase()));
                                    
                                    
                                    if(isEvery==true && valprod!=0){
                                      logicalimpact=json["Vulnerability"]["hasScenario"][e]["hasAction"][1]["resultsInImpact"][t]["hasLogicalImpact"].split("::").slice(-1)[0];
                                      privilegesgained=json["Vulnerability"]["hasScenario"][e]["hasAction"][1]["resultsInImpact"][t]["gainedPrivileges"]
                                      //console.log(privilegesgained);
                                      arraylinks=graph["links"];
                                      arraynodes=graph["nodes"];
                                      //console.log(graph["links"].length);
                                      //console.log(graph["nodes"].length);
                                      //console.log(idvul);      
                                      //console.log(issource);               
                                      for(var p=0; p<arraylinks.length; p++){
                                        if(idvul==arraylinks[p]["source"]){
                                          for(var m=0; m<arraylinks.length; m++){
                                            if(issource!=arraylinks[p]["target"] && arraylinks[p]["target"]==arraylinks[m]["source"] && parseInt(arraylinks[m]["target"])!=1){
                                              //console.log(arraylinks[p]["target"],arraylinks[m]["source"]);
                                              issource=arraylinks[p]["target"];
                                              //console.log(issource)
                                             /* newtarget=parseInt(arraynodes.length+1)
                                              newlinkr={"source":parseInt(arraylinks[m]["target"]),"target":newtarget};
                                              newtargeta=parseInt(newtarget+1)
                                              newlinka={"source":newtarget,"target":newtargeta};
                                              newnoder={id: newtarget, group: 2, label: "RULE "+newtarget+" ("+logicalimpact+"):0"}
                                              newnodea={id: newtargeta, group: 1, label: "gainsPrivilege"+"('"+address+"'"+privilegesgained+"):0"}
                                              arraylinks.push(newlinkr);
                                              arraylinks.push(newlinka);
                                              arraynodes.push(newnoder);
                                              arraynodes.push(newnodea);*/
                                              //issource=graph["links"].findIndex(obj => obj.source == idvul);
                                              //console.log(issource);
                                              newtarget=parseInt(arraynodes.length+1)
                                              newlinkr={"source":parseInt(issource),"target":newtarget};
                                              //newtargeta=parseInt(newtarget+1)
                                              //newlinka={"source":newtarget,"target":newtargeta};
                                              //newnoder={id: newtarget, group: 2, label: "RULE "+newtarget+" ("+logicalimpact+"):0"}
                                              newnoder={id: newtarget, group: 1, label: "gainsPrivilege"+"('"+address+"'"+privilegesgained+"):0"}
                                              arraylinks.push(newlinkr);
                                              //arraylinks.push(newlinka);
                                              arraynodes.push(newnoder);
                                              //arraynodes.push(newnodea);
                                              var weaknesses=json["Vulnerability"]["hasScenario"][e]["hasExploitedWeakness"];
                                              
                                              if(logicalimpact=="Service Interrupt"){
                                                for(var z=0; z<arraynodes.length; z++){
                                                  if(arraynodes[z]["label"].indexOf("physicalDamage")==0){
                                                    newlinkr={"source":newtargeta,"target":arraynodes[z-1]["id"]};
                                                    arraylinks.push(newlinkr);
                                                  } 
                                                }
                                                
                                              }
                                            
                                              for(var y=0; y<jsonfiles.length; y++){
                                                
                                                
                                                
                                                var n=jsonfiles[y];
                                                
                                                $.getJSON("./vdo/"+n, function(donnee){
                                                  
                                                  newcve=donnee["Vulnerability"]["hasIdentity"][0]["value"];
                                                  privilegesneeded=donnee["Vulnerability"]["hasScenario"][0]["barrier"][0]["neededPrivileges"]
                                                  //console.log(privilegesneeded);
                                                  //console.log(lastcve,newcve);
                                                  var caction;
                                                  var cprivileges;
                                                  var casset;
                                                  
                                                  for(var u=0; u<donnee["Vulnerability"]["hasScenario"].length; u++){
                                                    for(var h=0; h<donnee["Vulnerability"]["hasScenario"][u]["affectsProduct"]["hasEnumeration"]["values"].length; h++){
                                                      prod1=donnee["Vulnerability"]["hasScenario"][u]["affectsProduct"]["hasEnumeration"]["values"][h].split(':')[4];
                                                      products.push(prod1.split("_")[0]);
                                                      if(!products.includes(prod2)){
                                                        products.push(prod2);
                                                      }
                                                      
                                                                                             
                                                    }
                                                    if(donnee["Vulnerability"]["hasScenario"][u]["requiresAttackTheatre"]=="Internet"){
                                                      mean="remoteExploit";
                                                      
                                                    }
                                                    user=donnee["Vulnerability"]["hasScenario"][u]["barrier"][0]["neededPrivileges"];
                                                    //console.log(donnee["Vulnerability"]["hasScenario"][u]["hasAction"].slice(-1)[0]);
                                                    newimpact=donnee["Vulnerability"]["hasScenario"][u]["hasAction"].slice(-1)[0]["resultsInImpact"][0]["hasLogicalImpact"].split('::')[1];
                                                    impactmethod=donnee["Vulnerability"]["hasScenario"][u]["hasAction"].slice(-1)[0]["hasImpactMethod"];
                                                    caction=donnee["Vulnerability"]["hasScenario"][u]["barrier"][0]["blockedByBarrier"];
                                                    cprivileges=donnee["Vulnerability"]["hasScenario"][u]["barrier"][0]["neededPrivileges"];
                                                    casset=donnee["Vulnerability"]["hasScenario"][u]["barrier"][0]["relatesToContext"];
                                                    
                                                    
                                                  }
                                                  //donnees={"cve":newcve,"user":user,"newimpact":newimpact,"caction":caction,"cprivileges":cprivileges,"casset":casset,"products":products,"mean":mean,"precondition":precondition}
                                                  //console.log(lastcve,newcve);
                                                  donnees={"lastcve":lastcve,"cve":newcve,"user":user,"newimpact":newimpact,"impactmethod":impactmethod,"caction":caction,"cprivileges":cprivileges,"casset":casset,"products":products,"mean":mean}
                                                  products=[];
                                                  arraydonnees.push(donnees);
                                                  //console.log(donnees);
                                                  localStorage.setItem('arraydonnees',JSON.stringify(arraydonnees,null,4));                     
                                                })
                                                            
                                              
                                              }
                                              lengthdonnee=JSON.parse(localStorage.getItem('arraydonnees'));
                                              
                                              for(z=0; z<lengthdonnee.length; z++){
                                                //console.log(lengthdonnee[z]["lastcve"]);
                                                //if(weaknesses.includes(lengthdonnee[z]["precondition"]) && lengthdonnee[z]["products"].includes(product)){
                                                //console.log(lengthdonnee[z]["products"],product)
                                                if(privilegesgained==lengthdonnee[z]["cprivileges"] && lengthdonnee[z]["products"].includes(product)){
                                                    
                                                  if(!arrayremovenodes.includes(lengthdonnee[z]["cve"]) && lengthdonnee[z]["lastcve"]!=lengthdonnee[z]["cve"]){
                                                    arrayremovenodes.push(lengthdonnee[z]["cve"]);
                                                    countpostcondition=countpostcondition+1;
                                                    if(arraycve.includes(lengthdonnee[z]["cve"])){
                                                      
                                                      var position=arraycve.findIndex(obj => obj ==lengthdonnee[z]["cve"]);
                                                      newtargeta=arrayid[position];
                                                      //console.log(newtarget,newtargeta);
                                                      newlinkr={"source":newtarget,"target":newtargeta};
                                                      arraylinks.push(newlinkr);
  
                                                    }
                                                    else{
                                                      
                                                      newtarget=parseInt(arraynodes.length+1)
                                                      newtargeto=parseInt(newtarget+1);
                                                      newtargetv=parseInt(newtargeto+1)
                                                      newlinkr={"source":newtargeta,"target":newtargeto};
                                                      newlinka={"source":newtarget,"target":newtargeto};
                                                      newlinkv={"source":newtargeto,"target":newtargetv};
                                                      newnoder={id:newtarget, group: 4, label: "vulExists"+"('"+address+"',"+"'"+lengthdonnee[z]["cve"]+"'"+","+product+","+lengthdonnee[z]["mean"]+","+lengthdonnee[z]["newimpact"]+"):0"}
                                                      newnodea={id:newtargeto, group: 2, label: "RULE "+newtargeto+" ("+lengthdonnee[z]["impactmethod"][0]+"):0"};
                                                      if(lengthdonnee[z]["impactmethod"][0]=='Code Execution'){
                                                        newnodev={id:newtargetv, group: 1, label: "execCode ('"+address+"',"+lengthdonnee[z]["user"]+")"}
                                                      }
                                                      if(lengthdonnee[z]["impactmethod"][0]=='Authentication Bypass'){
                                                        newnodev={id:newtargetv, group: 1, label: "bypassAut ('"+address+"',"+lengthdonnee[z]["user"]+")"}
                                                      }
                                                      if(lengthdonnee[z]["impactmethod"][0]=='Context Escape'){
                                                        newnodev={id:newtargetv, group: 1, label: "escapeContext ('"+address+"',"+lengthdonnee[z]["user"]+")"}
                                                      }
                                                      
                                                      arraylinks.push(newlinkr);
                                                      arraynodes.push(newnoder);
                                                      arraylinks.push(newlinka);
                                                      arraynodes.push(newnodea);
                                                      arraylinks.push(newlinkv);
                                                      arraynodes.push(newnodev);
                                                    }
                                                    
                                                    localStorage.setItem('counter','remove '+lengthdonnee[z]["user"]+' as '+lengthdonnee[z]["cprivileges"]+' on ' + lengthdonnee[z]["casset"]);
                                                    localStorage.setItem('newcve',lengthdonnee[z]["cve"]);
                                                    localStorage.setItem('lastcve',lengthdonnee[z]["lastcve"]);
                                                    //console.log(localStorage.getItem("lastcve"));

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
                                                        "Countermeasure": localStorage.getItem('counter'),
                                                        "Status": "Post-condition of "+localStorage.getItem('lastcve')
                                                    }
                                                    }
                                                    arraykafka.push(kafkajson);
                                                    
                                                   if(countpostcondition==arraykafka.length){
                                                      localStorage.setItem('alerte',JSON.stringify(arraykafka,null,4));
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
                                                  }
                                                }
                                              
            
                                                newnoder={};
                                                newlinkr={};
                                                newnodea={};
                                                newlinka={};
                                                newnodev={};
                                                newlinkv={};
                                                jsonfinal={"nodes":arraynodes,"links":arraylinks};
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
                               
                              }
                              
                              
                            }
                          }
                          localStorage.setItem("someVarKey", cve);
                          localStorage.setItem('sendalert',2);
                          //console.log(localStorage.getItem("someVarKey"));
                        //}
                      }); 
                  }
                });
                
                arraynodes=graph["nodes"]; 
                arraylinks=graph["links"];
                jsonfinal={"nodes":arraynodes,"links":arraylinks};
                localStorage.setItem('myjson',JSON.stringify(jsonfinal,null,4));
                obj=JSON.parse(localStorage.getItem('myjson'));     
                //localStorage.setItem("someVarKey", null);                  
              }
              else{
                localStorage.setItem('sendalert',2);
              }
              
            }
          }
        }
        
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
  }
  
  }
  for (var i = 0; i < graph["nodes"].length; i++){
    var hacl=graph["nodes"][i]["label"].indexOf("hacl");
    var net=graph["nodes"][i]["label"].indexOf("networkServiceInfo");
    var acc=graph["nodes"][i]["label"].indexOf("hasAccount");
    var mal=graph["nodes"][i]["label"].indexOf("accessMaliciousInput");
    var ch;
    var protocolsep;
    var portsep;

    if(severity=="high" || severity=="medium" || severity=="low"){
      if(hacl==0){
        var sep=graph["nodes"][i]["label"].split(',');
        adds=sep[0].split("'")[1];
        //console.log(adds);
        protocolsep=sep[2];
        portsep=sep[3].split(")")[0];
        

        if(adds==addresssource && sep[2]==protocol && parseInt(sep[3].split("):")[0])==parseInt(port)){
          ch=1
          
        }
        
      }
      //console.log(mal,net,acc, graph["nodes"][i]["label"]);
      if(acc==0){
        //console.log(acc, mal, graph["nodes"][i]["label"]);
        var sepacc=graph["nodes"][i]["label"];
        var addsep=sepacc.split("'")[1];
        for (var i = 0; i < graph["nodes"].length; i++){
          mal=graph["nodes"][i]["label"].indexOf("accessMaliciousInput");
          //acc=graph["nodes"][i]["label"].indexOf("hasAccount");
          if(mal==0){
            var sep=graph["nodes"][i]["label"].split(',');
            add=sep[0].split("'")[1];
            addsource=sep[0].split("'")[0];
            //console.log(port, protocol);
            if(sep[2]!="no_products" && add==address && adds==address && portsep==port && protocolsep==protocol){
              //console.log(acc, mal, sep[2].split(')'));
              pros=sep[2].split(')')[0];
              product=sep[2].split(")")[0].replace("'","");
              //console.log(product);
              for (var i = 0; i < graph["nodes"].length; i++){
          
                var vul=graph["nodes"][i]["label"].indexOf("vulExists");
                
                if(vul==0){
                  addvul=graph["nodes"][i]["label"].split(',')[0].split("'")[1];
                  prodvul=graph["nodes"][i]["label"].split(',')[2];
                  cve=graph["nodes"][i]["label"].split(",")[1].split("'")[1];
                  impact=graph["nodes"][i]["label"].split(',')[4].split(")")[0];
                  if(addvul==add && prodvul==pros){
                    //console.log(prodvul,pros);
                    //console.log(vul,cve);
                    //console.log(graph["nodes"][i]["label"]);
                    idvul=graph["nodes"][i]["id"];
                    //console.log(cve,impact);
                    val=1;
                    val=0;
                    valprod=0;
                    var prod="";
                    var prod2="";
                    var arraylinks=[];
                    var arraynodes=[];
                    var newlinkr={};
                    var newnoder={};
                    var newlinka={};
                    var newnodea={};
                    var newlinkv={};
                    var newnodev={};
                    var onto="vdo/"+cve+"json";
                    var seps=impact.split(/(?=[A-Z])/);
                    var precondition='';
                    var products=[];
                    var newcve='';
                    var user='';
                    var mean='';
                    var newimpact='';
                    var impactmethod='';
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
                    var lastcve='';
                    
                    
                    var name=localStorage.getItem('someVarKey');
      
                    if(localStorage.getItem('someVarKey')=="null" && cve!="CVE-XXXX-XXXX"){   
      
                      objIndex = graph["nodes"].findIndex((obj => obj.id == idvul));
            
                      graph["nodes"][objIndex].group = 6;
                      $.ajax({
                        dataType: "json",
                        data:cve,
                        url: "../scriptphp/countermeasure.json",
                        dataType: "json",
                        async: false, 
                        success: function(data) {
                          countermeasure=data["counter"].findIndex((obj => obj.CVE == cve));
                          localStorage.setItem("cr",data["counter"][countermeasure]["Countermeasure"]);
                            kafkajson={
                              "Header": {
                              "Source": "CTM",      
                              "Timestamp": timestamp,      
                              "Criticality": "high",      
                              "Description": "CTM / Cyber Vulnerability"
                              },      
                              "Payload": {      
                              "CVEID": cve,      
                              "IP address": address,      
                              "Product": product,      
                              "User Name": username,      
                              "Countermeasure": localStorage.getItem("cr"),
                              "Status": "Exploited"
                              }
                            }
                            arraykafka.push(kafkajson);
                            localStorage.setItem('alerte',JSON.stringify(arraykafka,null,4));
                            localStorage.setItem('sendalert',1);
                            const alertes =  localStorage.getItem("alerte");
                            const jsonString = alertes;
                            var localcve=JSON.parse(localStorage.getItem("cveliste"));
                            if(!localcve.includes(cve)){
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
                                cveliste.push(cve);
                                localStorage.setItem("cveliste",JSON.stringify(cveliste));
                                //console.log(JSON.parse(localStorage.getItem("cveliste")));
                            }
                            listcve=JSON.parse(localStorage.getItem("cveliste"));
                            //console.log(listcve);
                            $.getJSON("./vdo/"+cve+".json", function(json) {
                              //lastcve=json["Vulnerability"]["hasIdentity"][0]["value"];
                              //console.log(listcve.length,cve);
                              lastcve=cve;
                              //if(json["Vulnerability"]["hasIdentity"][0]["value"]==cve){
                                
                                
                                for(var e=0; e<json["Vulnerability"]["hasScenario"].length; e++){
                                  for(var b=0; b<json["Vulnerability"]["hasScenario"][e]["affectsProduct"]["hasEnumeration"]["values"].length; b++){
                                    prod=json["Vulnerability"]["hasScenario"][e]["affectsProduct"]["hasEnumeration"]["values"][b].split(':')[4];
                                    prod2=json["Vulnerability"]["hasScenario"][e]["affectsProduct"]["hasEnumeration"]["values"][b].split(':')[3];
                                    //console.log(prod.split('_')[0],prod2,pros);
                                    if(prod.split('_')[0]==product || prod2==product){
                                      valprod=1;
                                      
                                    }
                                  }
                                  
                                  for(var o=0; o<json["Vulnerability"]["hasScenario"][e]["hasAction"].length; o++){
                                    //console.log(prod,prod2);
                                    if(json["Vulnerability"]["hasScenario"][e]["hasAction"][o]["resultsInImpact"].length>=1){
                                      for(var t=0; t<json["Vulnerability"]["hasScenario"][e]["hasAction"][o]["resultsInImpact"].length; t++){
                                        if(o==1){
                                          
                                          check=json["Vulnerability"]["hasScenario"][e]["hasAction"][o]["resultsInImpact"][t]["hasLogicalImpact"]
                      
                                          var isEvery = seps.every(item => check.toLowerCase().includes(item.toLowerCase()));
                                          
                                          
                                          if(isEvery==true && valprod!=0){
                                            logicalimpact=json["Vulnerability"]["hasScenario"][e]["hasAction"][1]["resultsInImpact"][t]["hasLogicalImpact"].split("::").slice(-1)[0];
                                            privilegesgained=json["Vulnerability"]["hasScenario"][e]["hasAction"][1]["resultsInImpact"][t]["gainedPrivileges"]
                                            //console.log(privilegesgained);
                                            arraylinks=graph["links"];
                                            arraynodes=graph["nodes"];
                                            //console.log(graph["links"].length);
                                            //console.log(graph["nodes"].length);
                                            //console.log(idvul);      
                                            console.log(issource);               
                                            for(var p=0; p<arraylinks.length; p++){
                                              if(idvul==arraylinks[p]["source"]){
                                                for(var m=0; m<arraylinks.length; m++){
                                                  if(issource!=arraylinks[p]["target"] && arraylinks[p]["target"]==arraylinks[m]["source"] && parseInt(arraylinks[m]["target"])!=1){
                                                    //console.log(arraylinks[p]["target"],arraylinks[m]["source"]);
                                                    issource=arraylinks[p]["target"];
                                                    //console.log(issource)
                                                   /* newtarget=parseInt(arraynodes.length+1)
                                                    newlinkr={"source":parseInt(arraylinks[m]["target"]),"target":newtarget};
                                                    newtargeta=parseInt(newtarget+1)
                                                    newlinka={"source":newtarget,"target":newtargeta};
                                                    newnoder={id: newtarget, group: 2, label: "RULE "+newtarget+" ("+logicalimpact+"):0"}
                                                    newnodea={id: newtargeta, group: 1, label: "gainsPrivilege"+"('"+address+"'"+privilegesgained+"):0"}
                                                    arraylinks.push(newlinkr);
                                                    arraylinks.push(newlinka);
                                                    arraynodes.push(newnoder);
                                                    arraynodes.push(newnodea);*/
                                                    //issource=graph["links"].findIndex(obj => obj.source == idvul);
                                                    //console.log(issource);
                                                    newtarget=parseInt(arraynodes.length+1)
                                                    newlinkr={"source":parseInt(issource),"target":newtarget};
                                                    //newtargeta=parseInt(newtarget+1)
                                                    //newlinka={"source":newtarget,"target":newtargeta};
                                                    //newnoder={id: newtarget, group: 2, label: "RULE "+newtarget+" ("+logicalimpact+"):0"}
                                                    newnoder={id: newtarget, group: 1, label: "gainsPrivilege"+"('"+address+"'"+privilegesgained+"):0"}
                                                    arraylinks.push(newlinkr);
                                                    //arraylinks.push(newlinka);
                                                    arraynodes.push(newnoder);
                                                    //arraynodes.push(newnodea);
                                                    var weaknesses=json["Vulnerability"]["hasScenario"][e]["hasExploitedWeakness"];
                                                    
                                                    if(logicalimpact=="Service Interrupt"){
                                                      for(var z=0; z<arraynodes.length; z++){
                                                        if(arraynodes[z]["label"].indexOf("physicalDamage")==0){
                                                          newlinkr={"source":newtargeta,"target":arraynodes[z-1]["id"]};
                                                          arraylinks.push(newlinkr);
                                                        } 
                                                      }
                                                      
                                                    }
                                                  
                                                    for(var y=0; y<jsonfiles.length; y++){
                                                      
                                                      
                                                      
                                                      var n=jsonfiles[y];
                                                      
                                                      $.getJSON("./vdo/"+n, function(donnee){
                                                        
                                                        newcve=donnee["Vulnerability"]["hasIdentity"][0]["value"];
                                                        privilegesneeded=donnee["Vulnerability"]["hasScenario"][0]["barrier"][0]["neededPrivileges"]
                                                        //console.log(privilegesneeded);
                                                        //console.log(lastcve,newcve);
                                                        var caction;
                                                        var cprivileges;
                                                        var casset;
                                                        
                                                        for(var u=0; u<donnee["Vulnerability"]["hasScenario"].length; u++){
                                                          for(var h=0; h<donnee["Vulnerability"]["hasScenario"][u]["affectsProduct"]["hasEnumeration"]["values"].length; h++){
                                                            prod1=donnee["Vulnerability"]["hasScenario"][u]["affectsProduct"]["hasEnumeration"]["values"][h].split(':')[4];
                                                            products.push(prod1.split("_")[0]);
                                                            if(!products.includes(prod2)){
                                                              products.push(prod2);
                                                            }
                                                            
                                                                                                   
                                                          }
                                                          if(donnee["Vulnerability"]["hasScenario"][u]["requiresAttackTheatre"]=="Internet"){
                                                            mean="remoteExploit";
                                                            
                                                          }
                                                          user=donnee["Vulnerability"]["hasScenario"][u]["barrier"][0]["neededPrivileges"];
                                                          //console.log(donnee["Vulnerability"]["hasScenario"][u]["hasAction"].slice(-1)[0]);
                                                          newimpact=donnee["Vulnerability"]["hasScenario"][u]["hasAction"].slice(-1)[0]["resultsInImpact"][0]["hasLogicalImpact"].split('::')[1];
                                                          impactmethod=donnee["Vulnerability"]["hasScenario"][u]["hasAction"].slice(-1)[0]["hasImpactMethod"];
                                                          caction=donnee["Vulnerability"]["hasScenario"][u]["barrier"][0]["blockedByBarrier"];
                                                          cprivileges=donnee["Vulnerability"]["hasScenario"][u]["barrier"][0]["neededPrivileges"];
                                                          casset=donnee["Vulnerability"]["hasScenario"][u]["barrier"][0]["relatesToContext"];
                                                          
                                                          
                                                        }
                                                        //donnees={"cve":newcve,"user":user,"newimpact":newimpact,"caction":caction,"cprivileges":cprivileges,"casset":casset,"products":products,"mean":mean,"precondition":precondition}
                                                        //console.log(lastcve,newcve);
                                                        donnees={"lastcve":lastcve,"cve":newcve,"user":user,"newimpact":newimpact,"impactmethod":impactmethod,"caction":caction,"cprivileges":cprivileges,"casset":casset,"products":products,"mean":mean}
                                                        products=[];
                                                        arraydonnees.push(donnees);
                                                        //console.log(donnees);
                                                        localStorage.setItem('arraydonnees',JSON.stringify(arraydonnees,null,4));                     
                                                      })
                                                                  
                                                    
                                                    }
                                                    lengthdonnee=JSON.parse(localStorage.getItem('arraydonnees'));
                                                    
                                                    for(z=0; z<lengthdonnee.length; z++){
                                                      //console.log(lengthdonnee[z]["lastcve"]);
                                                      //if(weaknesses.includes(lengthdonnee[z]["precondition"]) && lengthdonnee[z]["products"].includes(product)){
                                                      //console.log(lengthdonnee[z]["products"],product)
                                                      if(privilegesgained==lengthdonnee[z]["cprivileges"] && lengthdonnee[z]["products"].includes(product)){
                                                          
                                                        if(!arrayremovenodes.includes(lengthdonnee[z]["cve"]) && lengthdonnee[z]["lastcve"]!=lengthdonnee[z]["cve"]){
                                                          arrayremovenodes.push(lengthdonnee[z]["cve"]);
                                                          countpostcondition=countpostcondition+1;
                                                          if(arraycve.includes(lengthdonnee[z]["cve"])){
                                                            
                                                            var position=arraycve.findIndex(obj => obj ==lengthdonnee[z]["cve"]);
                                                            newtargeta=arrayid[position];
                                                            //console.log(newtarget,newtargeta);
                                                            newlinkr={"source":newtarget,"target":newtargeta};
                                                            arraylinks.push(newlinkr);
        
                                                          }
                                                          else{
                                                            
                                                            newtarget=parseInt(arraynodes.length+1)
                                                            newtargeto=parseInt(newtarget+1);
                                                            newtargetv=parseInt(newtargeto+1)
                                                            newlinkr={"source":newtargeta,"target":newtargeto};
                                                            newlinka={"source":newtarget,"target":newtargeto};
                                                            newlinkv={"source":newtargeto,"target":newtargetv};
                                                            newnoder={id:newtarget, group: 4, label: "vulExists"+"('"+address+"',"+"'"+lengthdonnee[z]["cve"]+"'"+","+product+","+lengthdonnee[z]["mean"]+","+lengthdonnee[z]["newimpact"]+"):0"}
                                                            newnodea={id:newtargeto, group: 2, label: "RULE "+newtargeto+" ("+lengthdonnee[z]["impactmethod"][0]+"):0"};
                                                            if(lengthdonnee[z]["impactmethod"][0]=='Code Execution'){
                                                              newnodev={id:newtargetv, group: 1, label: "execCode ('"+address+"',"+lengthdonnee[z]["user"]+")"}
                                                            }
                                                            if(lengthdonnee[z]["impactmethod"][0]=='Authentication Bypass'){
                                                              newnodev={id:newtargetv, group: 1, label: "bypassAut ('"+address+"',"+lengthdonnee[z]["user"]+")"}
                                                            }
                                                            if(lengthdonnee[z]["impactmethod"][0]=='Context Escape'){
                                                              newnodev={id:newtargetv, group: 1, label: "escapeContext ('"+address+"',"+lengthdonnee[z]["user"]+")"}
                                                            }
                                                            
                                                            arraylinks.push(newlinkr);
                                                            arraynodes.push(newnoder);
                                                            arraylinks.push(newlinka);
                                                            arraynodes.push(newnodea);
                                                            arraylinks.push(newlinkv);
                                                            arraynodes.push(newnodev);
                                                          }
                                                          
                                                          localStorage.setItem('counter','remove '+lengthdonnee[z]["user"]+' as '+lengthdonnee[z]["cprivileges"]+' on ' + lengthdonnee[z]["casset"]);
                                                          localStorage.setItem('newcve',lengthdonnee[z]["cve"]);
                                                          localStorage.setItem('lastcve',lengthdonnee[z]["lastcve"]);
                                                          console.log(localStorage.getItem("lastcve"));
      
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
                                                              "Countermeasure": localStorage.getItem('counter'),
                                                              "Status": "Post-condition of "+localStorage.getItem('lastcve')
                                                          }
                                                          }
                                                          arraykafka.push(kafkajson);
                                                          
                                                         if(countpostcondition==arraykafka.length){
                                                            localStorage.setItem('alerte',JSON.stringify(arraykafka,null,4));
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
                                                        }
                                                      }
                                                    
                  
                                                      newnoder={};
                                                      newlinkr={};
                                                      newnodea={};
                                                      newlinka={};
                                                      newnodev={};
                                                      newlinkv={};
                                                      jsonfinal={"nodes":arraynodes,"links":arraylinks};
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
                                     
                                    }
                                    
                                    
                                  }
                                }
                                localStorage.setItem("someVarKey", cve);
                                localStorage.setItem('sendalert',2);
                                //console.log(localStorage.getItem("someVarKey"));
                              //}
                            }); 
                        }
                      });
                      arraynodes=graph["nodes"]; 
                      arraylinks=graph["links"];
                      jsonfinal={"nodes":arraynodes,"links":arraylinks};
                      localStorage.setItem('myjson',JSON.stringify(jsonfinal,null,4));
                      obj=JSON.parse(localStorage.getItem('myjson'));     
                      //localStorage.setItem("someVarKey", null);                  
                    }
                    else{
                      localStorage.setItem('sendalert',2);
                    }
                    
                  }
                }
              }
            }
          }
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
  localStorage.setItem("cveliste",JSON.stringify([]));
  var link = document.getElementById("home");
  link.setAttribute("href", "./index.html");
  return true;
  location.reload(true);
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
