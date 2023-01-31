function updateGraph(){
  graph = JSON.parse(localStorage.getItem('myjson'))
  var val=0;
  var idvul=0;
  var cve='';
  var product="";
  var address=document.getElementById("your-hidden-address").value;
  var protocol=document.getElementById("your-hidden-protocol").value;
  var port=document.getElementById("your-hidden-port").value;
  var severity=document.getElementById("your-hidden-severity").value;
  var addresssource=document.getElementById("your-hidden-addresssource").value;
  var timestamp=document.getElementById("your-hidden-timestamp").value;
  var username='';
  var kafkajson;
  var arrayip=[];
  var arraycve=[];
  var arrayid=[];
  var cveliste=[];
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
    
  if(severity=="high"){
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
      if(sep[1]!="no_products" && add==address && sep[2]==protocol && parseInt(sep[3].split("):")[0].split("'")[1])==parseInt(port)){
        
  
        pros=sep[1];
        product=sep[1].split(" ")[0].replace("'","");
        username=sep[4].split(")")[0];
        for (var i = 0; i < graph["nodes"].length; i++){
          var vul=graph["nodes"][i]["label"].indexOf("vulExists");
          
          if(vul==0){
            addvul=graph["nodes"][i]["label"].split(',')[0].split("'")[1];
            prodvul=graph["nodes"][i]["label"].split(',')[2];
            cve=graph["nodes"][i]["label"].split(",")[1].split("'")[1];
            impact=graph["nodes"][i]["label"].split(',')[4].split(")")[0];
            if(addvul==add && prodvul==pros){
              idvul=graph["nodes"][i]["id"];
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
              var datapost={};
              var arraydonnees=[];
              var arraypost=[];
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
              var addresslist=[];
              
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
                      }
                      
                      listcve=JSON.parse(localStorage.getItem("cveliste"));          
                      $.ajax({
                        type: 'POST',
                        url: "../scriptphp/executequerypos.php",
                        dataType: "json",
                        global:"false",
                        async :"true",
                        data :{cveid:cve, prod:product},
                        context: document.body,
                        success: function(data){
                          arraykafka=[];
                          
                        }
                      })  
                      $.getJSON("../scriptphp/postcon.json",function(post){
                            
                            for(var op=0; op<post.length; op++){
                              if(post[op]["mean"]=="Internet"){
                                mean="remoteExploit";
                              }
                              user=post[op]["privilege"];                         
                              newimpact=post[op]["impact"];
                              impactmethod=post[op]["impactMethod"];
                              caction=post[op]["barrier"];
                              cprivileges=post[op]["privilege"];
                              casset=product;
                              lastcve=post[op]["lastcve"];
                              neededprivilege=post[op]["neededPrivileges"]
                              var newidvul=lastcve;
                              newcve=post[op]["postcondition"];
                              datapost={"lastcve":lastcve,"cve":newcve,"user":user,"newimpact":newimpact,"impactmethod":impactmethod,"caction":caction,"cprivileges":cprivileges,"casset":casset,"mean":mean,"neededprivilege":neededprivilege}
                              products=[];
                              arraypost.push(datapost);

                              localStorage.setItem('arraypost',JSON.stringify(arraypost,null,4));
                              lengthdonnee=JSON.parse(localStorage.getItem('arraypost'));

                            }
                            arraylinks=graph["links"];
                            arraynodes=graph["nodes"]; 
                            arraykafka=[];    
                              
                            var newid=0;
                            arraylinks.forEach((label)=>label["source"]==idvul?newid=label["target"]:null);
                            //console.log(newid);
                            arraylinks.forEach((label)=>label["source"]==newid?idvul=label["target"]:null);
                            //console.log(idvul);
                            issource=idvul;          
                            for(z=0; z<lengthdonnee.length; z++){
                              if(lengthdonnee[z]["cprivileges"]=="Privileged"||lengthdonnee[z]["cprivileges"]=="Administrator"){
                                      
                                
                                
                                if(arraycve.includes(lengthdonnee[z]["cve"])){
                                                                            
                                  var result = [];
                                  
                                  arraycve.forEach((car, index) => car === lengthdonnee[z]["cve"] ? result.push(index) : null)
                                  
                                  if(!arrayremovenodes.includes(lengthdonnee[z]["lastcve"])){
                                    
                                    arrayremovenodes.push(lengthdonnee[z]["lastcve"]);
                                    
                                    newtarget=parseInt(arraynodes.length+1)
                                    newlinkr={"source":parseInt(issource),"target":newtarget};
                                          
                                    //newnoder={id: newtarget, group: 1, label: "gainsPrivilege"+"('"+address+"'"+lengthdonnee[z]["cprivileges"]+"):0"}
                                    newnoder={id: newtarget, group: 2, label: "RULE 9 (gain privilege):0"} 

                                    arraylinks.push(newlinkr);
                                    arraynodes.push(newnoder);
                                                                                
                                  }
                                  if(!arrayremovenodes.includes(lengthdonnee[z]["cve"])){
                                    
                                    arrayremovenodes.push(lengthdonnee[z]["cve"]);
                                    var listaddress=[];
                                    arraynodes.forEach((label)=>label["label"].indexOf("vulExists")==0?label["label"].split(",")[1].split("'")[1]==lengthdonnee[z]["cve"]?listaddress.push(label["label"].split(",")[0].split("(")[1].split("'")[1]):null:null);

                                    
                                    for(el=0; el<result.length; el++){

                                      countpostcondition=countpostcondition+1;
                                      var position=result[el];
                                      newtargeta=arrayid[position]; 
                                      var idrule=0;
                                      arraylinks.forEach((label)=>label["source"]==arrayid[position]?idrule=label["target"]:null);
                                      newidrule=0;
                                      arraylinks.forEach((label)=>label["source"]==idrule?newidrule=label["target"]:null);
                                      newlinkr={"source":newtarget,"target":newidrule};
                                      
                                      arraylinks.push(newlinkr);
                                      
                                      
                                    
                                      localStorage.setItem('counter','remove '+username+' as '+lengthdonnee[z]["cprivileges"]+' on ' + lengthdonnee[z]["casset"]);
                                      localStorage.setItem('newcve',lengthdonnee[z]["cve"]);
                                      localStorage.setItem('lastcve',lengthdonnee[z]["lastcve"]);
                                      kafkajson={"Header": {
                                        "Source": "CTM",      
                                        "Timestamp": timestamp,      
                                        "Criticality": severity,      
                                        "Description": "CTM / Cyber Vulnerability"
                                        },      
                                        "Payload": {      
                                        "CVEID": localStorage.getItem('newcve'),      
                                        "IP address": listaddress[el],      
                                        "Product": product,      
                                        "User Name": username,      
                                        "Countermeasure": localStorage.getItem('counter'),
                                        "Status": "Post-condition of "+localStorage.getItem('lastcve')
                                        }
                                        }
                                      arraykafka.push(kafkajson);
                                    }   
                                    
                                  } 
     
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
                              else{
                                if(lengthdonnee[z]["neededprivilege"]!="Privileged"||lengthdonnee[z]["neededprivilege"]!="Administrator"){
                                  if(arraycve.includes(lengthdonnee[z]["cve"])){
                                                                            
                                    var result = [];
                                    
                                    arraycve.forEach((car, index) => car === lengthdonnee[z]["cve"] ? result.push(index) : null)
                                    
                                    if(!arrayremovenodes.includes(lengthdonnee[z]["lastcve"])){
                                      
                                      arrayremovenodes.push(lengthdonnee[z]["lastcve"]);
                                      
                                      newtarget=parseInt(arraynodes.length+1)
                                      newlinkr={"source":parseInt(issource),"target":newtarget};
                                            
                                      //newnoder={id: newtarget, group: 1, label: "gainsPrivilege"+"('"+address+"'"+lengthdonnee[z]["cprivileges"]+"):0"}
                                      newnoder={id: newtarget, group: 2, label: "RULE 9 (gain privilege):0"} 

                                      arraylinks.push(newlinkr);
                                      arraynodes.push(newnoder);
                                                                                  
                                    }
                                    if(!arrayremovenodes.includes(lengthdonnee[z]["cve"])){
                                      arrayremovenodes.push(lengthdonnee[z]["cve"]);
                                      var listaddress=[];
                                      arraynodes.forEach((label)=>label["label"].indexOf("vulExists")==0?label["label"].split(",")[1].split("'")[1]==lengthdonnee[z]["cve"]?listaddress.push(label["label"].split(",")[0].split("(")[1].split("'")[1]):null:null);

                                      for(el=0; el<result.length; el++){
                                        if(listaddress[el]==address){
                                          countpostcondition=countpostcondition+1;
                                          var position=result[el];
                                          newtargeta=arrayid[position]; 
                                          var idrule=0;
                                          arraylinks.forEach((label)=>label["source"]==arrayid[position]?idrule=label["target"]:null);
                                          newidrule=0;
                                          arraylinks.forEach((label)=>label["source"]==idrule?newidrule=label["target"]:null);
                                          newlinkr={"source":newtarget,"target":newidrule};
                                          arraylinks.push(newlinkr);
                                          
                                          localStorage.setItem('counter','remove '+username+' as '+lengthdonnee[z]["cprivileges"]+' on ' + lengthdonnee[z]["casset"]);
                                          localStorage.setItem('newcve',lengthdonnee[z]["cve"]);
                                          localStorage.setItem('lastcve',lengthdonnee[z]["lastcve"]);
                                          kafkajson={"Header": {
                                            "Source": "CTM",      
                                            "Timestamp": timestamp,      
                                            "Criticality": severity,      
                                            "Description": "CTM / Cyber Vulnerability"
                                            },      
                                            "Payload": {      
                                            "CVEID": localStorage.getItem('newcve'),      
                                            "IP address": listaddress[el],      
                                            "Product": product,      
                                            "User Name": username,      
                                            "Countermeasure": localStorage.getItem('counter'),
                                            "Status": "Post-condition of "+localStorage.getItem('lastcve')
                                            }
                                            }
                                          arraykafka.push(kafkajson);
                                        } 
                                      }
                                      
                                    } 
                                    
                                          
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

                            localStorage.setItem("someVarKey", cve);
                            localStorage.setItem('sendalert',2);
                          
                          })
                  }
                });
                
                arraynodes=graph["nodes"]; 
                arraylinks=graph["links"];    
                           
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

    if(severity=="high" || severity=="medium"){
      if(hacl==0){
        var sep=graph["nodes"][i]["label"].split(',');
        adds=sep[0].split("'")[1];
     
        protocolsep=sep[2];
        portsep=sep[3].split(")")[0];
        

        if(adds==addresssource && sep[2]==protocol && parseInt(sep[3].split("):")[0])==parseInt(port)){
          ch=1
          
        }
        
      }

      if(acc==0){
      
        var sepacc=graph["nodes"][i]["label"];
        var addsep=sepacc.split("'")[1];
        for (var i = 0; i < graph["nodes"].length; i++){
          mal=graph["nodes"][i]["label"].indexOf("accessMaliciousInput");
          
          if(mal==0){
            var sep=graph["nodes"][i]["label"].split(',');
            add=sep[0].split("'")[1];
            addsource=sep[0].split("'")[0];
    
            if(sep[2]!="no_products" && add==address && adds==address && portsep==port && protocolsep==protocol){

              pros=sep[2].split(')')[0];
              product=sep[2].split(")")[0].replace("'","");
              for (var i = 0; i < graph["nodes"].length; i++){
          
                var vul=graph["nodes"][i]["label"].indexOf("vulExists");
                if(vul==0){
                  addvul=graph["nodes"][i]["label"].split(',')[0].split("'")[1];
                  prodvul=graph["nodes"][i]["label"].split(',')[2];
                  cve=graph["nodes"][i]["label"].split(",")[1].split("'")[1];
                  impact=graph["nodes"][i]["label"].split(',')[4].split(")")[0];
                  if(addvul==add && prodvul==pros){
                    idvul=graph["nodes"][i]["id"];
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
                    var datapost={};
                    var arraydonnees=[];
                    var arraypost=[];
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
                    var addresslist=[];
                    
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
                            }
                            
                            listcve=JSON.parse(localStorage.getItem("cveliste"));          
                            $.ajax({
                              type: 'POST',
                              url: "../scriptphp/executequerypos.php",
                              dataType: "json",
                              global:"false",
                              async :"true",
                              data :{cveid:cve, prod:product},
                              context: document.body,
                              success: function(data){
                                arraykafka=[];
                                
                              }
                            })  
                            $.getJSON("../scriptphp/postcon.json",function(post){
                                  
                                  for(var op=0; op<post.length; op++){
                                    if(post[op]["mean"]=="Internet"){
                                      mean="remoteExploit";
                                    }
                                    user=post[op]["privilege"];                         
                                    newimpact=post[op]["impact"];
                                    impactmethod=post[op]["impactMethod"];
                                    caction=post[op]["barrier"];
                                    cprivileges=post[op]["privilege"];
                                    casset=product;
                                    lastcve=post[op]["lastcve"];
                                    neededprivilege=post[op]["neededPrivileges"]
                                    var newidvul=lastcve;
                                    newcve=post[op]["postcondition"];
                                    datapost={"lastcve":lastcve,"cve":newcve,"user":user,"newimpact":newimpact,"impactmethod":impactmethod,"caction":caction,"cprivileges":cprivileges,"casset":casset,"mean":mean,"neededprivilege":neededprivilege}
                                    products=[];
                                    arraypost.push(datapost);
      
                                    localStorage.setItem('arraypost',JSON.stringify(arraypost,null,4));
                                    lengthdonnee=JSON.parse(localStorage.getItem('arraypost'));
      
                                  }
                                  arraylinks=graph["links"];
                                  arraynodes=graph["nodes"]; 
                                  arraykafka=[];    
                                    
                                  var newid=0;
                                  arraylinks.forEach((label)=>label["source"]==idvul?newid=label["target"]:null);
                                  arraylinks.forEach((label)=>label["source"]==newid?idvul=label["target"]:null);
                                  issource=idvul;          
                                  for(z=0; z<lengthdonnee.length; z++){
                                    if(lengthdonnee[z]["cprivileges"]=="Privileged"||lengthdonnee[z]["cprivileges"]=="Administrator"){
                                      if(arraycve.includes(lengthdonnee[z]["cve"])){
                                                                                  
                                        var result = [];
                                        
                                        arraycve.forEach((car, index) => car === lengthdonnee[z]["cve"] ? result.push(index) : null)
                                        
                                        if(!arrayremovenodes.includes(lengthdonnee[z]["lastcve"])){
                                          
                                          arrayremovenodes.push(lengthdonnee[z]["lastcve"]);
                                          
                                          newtarget=parseInt(arraynodes.length+1)
                                          newlinkr={"source":parseInt(issource),"target":newtarget};
                                                
                                          //newnoder={id: newtarget, group: 1, label: "gainsPrivilege"+"('"+address+"'"+lengthdonnee[z]["cprivileges"]+"):0"}
                                          newnoder={id: newtarget, group: 2, label: "RULE 9 (gain privilege):0"}      

                                          arraylinks.push(newlinkr);
                                          arraynodes.push(newnoder);
                                                                                      
                                        }
                                        if(!arrayremovenodes.includes(lengthdonnee[z]["cve"])){
                                          
                                          arrayremovenodes.push(lengthdonnee[z]["cve"]);
                                          var listaddress=[];
                                          arraynodes.forEach((label)=>label["label"].indexOf("vulExists")==0?label["label"].split(",")[1].split("'")[1]==lengthdonnee[z]["cve"]?listaddress.push(label["label"].split(",")[0].split("(")[1].split("'")[1]):null:null);
      
                                          
                                          for(el=0; el<result.length; el++){
      
                                            countpostcondition=countpostcondition+1;
                                            var position=result[el];
                                            newtargeta=arrayid[position]; 
                                            var idrule=0;
                                            arraylinks.forEach((label)=>label["source"]==arrayid[position]?idrule=label["target"]:null);
                                            newidrule=0;
                                            arraylinks.forEach((label)=>label["source"]==idrule?newidrule=label["target"]:null);
                                            newlinkr={"source":newtarget,"target":newidrule};
                                            
                                            arraylinks.push(newlinkr);
                                            
                                            
                                          
                                            localStorage.setItem('counter','remove '+username+' as '+lengthdonnee[z]["cprivileges"]+' on ' + lengthdonnee[z]["casset"]);
                                            localStorage.setItem('newcve',lengthdonnee[z]["cve"]);
                                            localStorage.setItem('lastcve',lengthdonnee[z]["lastcve"]);
                                            kafkajson={"Header": {
                                              "Source": "CTM",      
                                              "Timestamp": timestamp,      
                                              "Criticality": severity,      
                                              "Description": "CTM / Cyber Vulnerability"
                                              },      
                                              "Payload": {      
                                              "CVEID": localStorage.getItem('newcve'),      
                                              "IP address": listaddress[el],      
                                              "Product": product,      
                                              "User Name": username,      
                                              "Countermeasure": localStorage.getItem('counter'),
                                              "Status": "Post-condition of "+localStorage.getItem('lastcve')
                                              }
                                              }
                                            arraykafka.push(kafkajson);
                                          }   
                                          
                                        } 
           
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
                                    else{
                                      if(lengthdonnee[z]["neededprivilege"]!="Privileged"||lengthdonnee[z]["neededprivilege"]!="Administrator"){
                                        if(arraycve.includes(lengthdonnee[z]["cve"])){
                                                                                  
                                          var result = [];
                                          
                                          arraycve.forEach((car, index) => car === lengthdonnee[z]["cve"] ? result.push(index) : null)
                                          
                                          if(!arrayremovenodes.includes(lengthdonnee[z]["lastcve"])){
                                            
                                            arrayremovenodes.push(lengthdonnee[z]["lastcve"]);
                                            
                                            newtarget=parseInt(arraynodes.length+1)
                                            newlinkr={"source":parseInt(issource),"target":newtarget};
                                                  
                                            //newnoder={id: newtarget, group: 1, label: "gainsPrivilege"+"('"+address+"'"+lengthdonnee[z]["cprivileges"]+"):0"}
                                            newnoder={id: newtarget, group: 2, label: "RULE 9 (gain privilege):0"} 

                                            arraylinks.push(newlinkr);
                                            arraynodes.push(newnoder);
                                                                                        
                                          }
                                          if(!arrayremovenodes.includes(lengthdonnee[z]["cve"])){
                                            arrayremovenodes.push(lengthdonnee[z]["cve"]);
                                            var listaddress=[];
                                            arraynodes.forEach((label)=>label["label"].indexOf("vulExists")==0?label["label"].split(",")[1].split("'")[1]==lengthdonnee[z]["cve"]?listaddress.push(label["label"].split(",")[0].split("(")[1].split("'")[1]):null:null);
      
                                            for(el=0; el<result.length; el++){
                                              if(listaddress[el]==address){
                                                countpostcondition=countpostcondition+1;
                                                var position=result[el];
                                                newtargeta=arrayid[position]; 
                                                var idrule=0;
                                                arraylinks.forEach((label)=>label["source"]==arrayid[position]?idrule=label["target"]:null);
                                                newidrule=0;
                                                arraylinks.forEach((label)=>label["source"]==idrule?newidrule=label["target"]:null);
                                                newlinkr={"source":newtarget,"target":newidrule};
                                                arraylinks.push(newlinkr);
                                                
                                                localStorage.setItem('counter','remove '+username+' as '+lengthdonnee[z]["cprivileges"]+' on ' + lengthdonnee[z]["casset"]);
                                                localStorage.setItem('newcve',lengthdonnee[z]["cve"]);
                                                localStorage.setItem('lastcve',lengthdonnee[z]["lastcve"]);
                                                kafkajson={"Header": {
                                                  "Source": "CTM",      
                                                  "Timestamp": timestamp,      
                                                  "Criticality": severity,      
                                                  "Description": "CTM / Cyber Vulnerability"
                                                  },      
                                                  "Payload": {      
                                                  "CVEID": localStorage.getItem('newcve'),      
                                                  "IP address": listaddress[el],      
                                                  "Product": product,      
                                                  "User Name": username,      
                                                  "Countermeasure": localStorage.getItem('counter'),
                                                  "Status": "Post-condition of "+localStorage.getItem('lastcve')
                                                  }
                                                  }
                                                arraykafka.push(kafkajson);
                                              } 
                                            }
                                            
                                          } 
                                                  
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
      
                                  localStorage.setItem("someVarKey", cve);
                                  localStorage.setItem('sendalert',2);
                                
                                })
                        }
                      });
                      
                      arraynodes=graph["nodes"]; 
                      arraylinks=graph["links"];    
                                 
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