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
  var listecvss=[];
  var listecve=[];
  var listevul=[];
  var listeprod=[];
  var listeadd=[];
  var listeaddsource=[];
  var listeportnet=[];
  var listeprotnet=[];
  var listeusername=[]
  var listeimpact=[];
  var addvul="";
  var listeidvul=[];
  var listeallcve=[];
  var listeproduct=[];
  var consequence="";
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
    var vul=graph["nodes"][i]["label"].indexOf("vulExists");
    var acc=graph["nodes"][i]["label"].indexOf("hasAccount");
    var mal=graph["nodes"][i]["label"].indexOf("accessMaliciousInput");
    addvul=graph["nodes"][i]["label"].split(',')[0].split("'")[1];
    if(vul==0 && addvul==address){
      prodvul=graph["nodes"][i]["label"].split(',')[2];
      impactvul=graph["nodes"][i]["label"].split(',')[4].split(")")[0];
      cve=graph["nodes"][i]["label"].split(",")[1].split("'")[1];
      idvul=graph["nodes"][i]["id"];
      listeidvul.push(idvul);
      listeallcve.push(cve);
      listeimpact.push(impactvul);

    }   
    if(net==0){
      var sep=graph["nodes"][i]["label"].split(',');
      add=sep[0].split("'")[1];
      addsource=sep[0].split("'")[1];
      portnet=parseInt(sep[3].split("):")[0].split("'")[1]);
      pros=sep[1]
      protnet=sep[2];
      username=sep[4].split(")")[0];
      listeprod.push(pros);
      listeportnet.push(portnet);
      listeadd.push(add);
      listeaddsource.push(addsource);
      listeprotnet.push(protnet);
      listeusername.push(username);
    }
    else{
      if(hacl==0){
        var sep=graph["nodes"][i]["label"].split(',');
        adds=sep[0].split("'")[1];
     
        protocolsep=sep[2];
        portsep=sep[3].split(")")[0];
        

        if(adds==addresssource && sep[2]==protocol && parseInt(sep[3].split("):")[0])==parseInt(port)){
          ch=1
          
        }   
      }
      if(acc==0 && adds==address){
      
        var sepacc=graph["nodes"][i]["label"];
        var addsep=sepacc.split("'")[1];
        for (var i = 0; i < graph["nodes"].length; i++){
          mal=graph["nodes"][i]["label"].indexOf("accessMaliciousInput");
          
          if(mal==0){
            var sep=graph["nodes"][i]["label"].split(',');
            add=sep[0].split("'")[1];
            addsource=sep[0].split("'")[0];
            username=sep[4].split(")")[0];
            listeprod.push(pros);
            listeportnet.push(portnet);
            listeadd.push(add);
            listeaddsource.push(addsource);
            listeprotnet.push(protnet);
            listeusername.push(username);
          }
        }
      }
    }
  }
  if(severity=="high" || severity=="medium"){
    for(var i = 0; i < listeprod.length; i++){
      add=listeadd[i];
      addsource=listeaddsource[i];
      portnet=listeportnet[i];
      pros=listeprod[i];
      username=listeusername[i];
      prot=listeprotnet[i];     
      //console.log(prot);
      if(pros!="no_products" && add==address && prot==protocol && parseInt(portnet)==parseInt(port)){
        for(var e= 0; e < listeallcve.length; e++){
          cve=listeallcve[e];
          idvul=listeidvul[e];
          consequence=listeimpact[e];
          $.ajax({
            dataType: "json",
            data:cve,
            url: "../scriptphp/countermeasure.json",
            dataType: "json",
            async: false, 
            success: function(data) {
              countermeasure=data["counter"].findIndex((obj => obj.CVE == cve && obj.IP==add && obj.Product==pros.split("'")[1]));
              if(data["counter"][countermeasure]!=undefined){
                listecvss.push(parseFloat(data["counter"][countermeasure]["CVSS"]))
                listecve.push(data["counter"][countermeasure]["CVE"])
                listevul.push(idvul); 
                listeproduct.push(pros.split("'")[1].split(" ")[0].replace("'",""));                  
              }   
            }
          });
        } 
        Array.prototype.max = function() {
          return Math.max.apply(null, this);
        };
        var maxcvss=listecvss.max();
        listecvss.forEach((car, index) => car === maxcvss ? cve=listecve[index] : null)
        listecvss.forEach((car, index) => car === maxcvss ? idvul=listevul[index] : null)
        listecvss.forEach((car, index) => car === maxcvss ? product=listeproduct[index] : null)
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
        var precondition='';
        var products=[];
        var newcve='';
        var user='';
        var mean='';
        var newimpact='';
        var impactmethod='';
        var donnees={};
        var datapost={};
        var impactnew="";
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
        var arrayimpact=[];
        var dataimpact={};
        var lengthdonnee2=[];
        
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
                        url: '../scriptphp/executeproducer.php',
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
                    //console.log(data)
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
                      arraynewid=[]  
                      var newid=0;
                      arraylinks.forEach((label)=>label["source"]==idvul?newid=label["target"]:null);
                      arraylinks.forEach((label)=>label["source"]==newid?issource=label["target"]:null);
                      //issource=idvul;          
                      for(z=0; z<lengthdonnee.length; z++){
                        if(lengthdonnee[z]["cprivileges"]=="Privileged"||lengthdonnee[z]["cprivileges"]=="Administrator"){
                                
                          
                          
                          if(arraycve.includes(lengthdonnee[z]["cve"])){
                                                                      
                            var result = [];
                            
                            arraycve.forEach((car, index) => car === lengthdonnee[z]["cve"] ? result.push(index) : null)
                            
                            if(!arrayremovenodes.includes(lengthdonnee[z]["lastcve"])){
                              
                              arrayremovenodes.push(lengthdonnee[z]["lastcve"]);
                              
                              newtarget=parseInt(arraynodes.length+1)
                              newlinkr={"source":parseInt(issource),"target":newtarget};
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
                                if(!arraynewid.includes(newidrule)){
                                  newlinkr={"source":newtarget,"target":newidrule};
                                  arraynewid.push(newidrule);
                                  arraylinks.push(newlinkr);
                                }

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
                                    if(!arraynewid.includes(newidrule)){
                                      newlinkr={"source":newtarget,"target":newidrule};
                                      arraynewid.push(newidrule);
                                      arraylinks.push(newlinkr);
                                    }
                                    
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
                $.ajax({
                  type: 'POST',
                  url: "../scriptphp/executequeryimp.php",
                  dataType: "json",
                  global:"false",
                  async :"true",
                  data :{cveid:cve, prod:product},
                  context: document.body,
                  success: function(data){
                    arraykafka=[];
                    //console.log(data)
                  }
                })
                $.getJSON("../scriptphp/impact.json",function(impact){
                  for(var imp=0; imp<impact.length; imp++){
                    impactnew=impact[imp]["impact"];
                    if(impactnew.split(/(?=[A-Z])/)[1]!=consequence.split(/(?=[A-Z])/)[1]){
                      dataimpact={"cve":impact[imp]["cve"],"newimpact":impactnew}
                      arrayimpact.push(dataimpact);

                      localStorage.setItem('arrayimpact',JSON.stringify(arrayimpact,null,4));
                      lengthdonnee2=JSON.parse(localStorage.getItem('arrayimpact'));
                      
                    }
                  }
                  arraylinks=graph["links"];
                  arraynodes=graph["nodes"]; 
                  arraykafka=[];    
                  arraynewid=[]  
                  var newid=0;
                  var idn=0;
                  arraylinks.forEach((label)=>label["source"]==idvul?idn=label["target"]:null);
                  arraylinks.forEach((label)=>label["source"]==idn?issource=label["target"]:null);
                  //issource=idvul; 
                  //console.log(idvul);
                  console.log(idvul,issource);
                  for(z=0; z<lengthdonnee2.length; z++){
                    //console.log(lengthdonnee2[z]["newimpact"]);
                    newtarget=parseInt(arraynodes.length+1)
                    newlinkr={"source":parseInt(issource),"target":newtarget};                           
                    newnoder={id: newtarget, group: 2, label: "RULE 9 ("+lengthdonnee2[z]["newimpact"]+"):0"} 
                    newtargeta=parseInt(newtarget+1)
                    newlinka={"source":newtarget,"target":newtargeta}
                    newnodea={id: newtargeta, group: 1, label: lengthdonnee2[z]["newimpact"]+"("+address+")"} 
                    /*console.log(address);
                    $.ajax
                    ({
                        type: "POST",
                        dataType : 'json',
                        async: true,
                        url: './scriptphp/newrules.php',
                        global:"false",
                        data : {address: address},
                        context :document.body,
                        success: function(response){
                          
                        },
                        failure:function(response){
                          console.log(response);
                        }
                    });
                    newnoder={};
                    newlinkr={};
                    newnodea={};
                    newlinka={};
                    jsonfinal={"nodes":arraynodes,"links":arraylinks};
                    localStorage.setItem('myjson',JSON.stringify(jsonfinal,null,4));
                    obj=JSON.parse(localStorage.getItem('myjson'));*/

                    if(lengthdonnee2[z]["newimpact"]=="Panic" || lengthdonnee2[z]["newimpact"]=="Reboot" || lengthdonnee2[z]["newimpact"]){
                      for(var z=0; z<arraynodes.length; z++){
                        if(arraynodes[z]["label"].indexOf("physicalDamage")==0){
                          arraylinks.push(newlinkr);
                          arraynodes.push(newnoder);
                          arraylinks.push(newlinka);
                          arraynodes.push(newnodea);
                          var idfact=arraynodes[z]["id"];
                          arraylinks.forEach((label)=>label["target"]==idfact?newid=label["source"]:null);
                          //console.log(newid);
                          //var idtarget = graph["nodes"].findIndex((obj => obj.id == newid));
                          var newtargetv=newtargeta+1;
                          newnodev={id: newtargetv, group: 2, label: "RULE 9 (Physical Damage):0"} ;
                          newlinkv={"source":newtargeta,"target":newtargetv};
                          arraylinks.push(newlinkv);
                          arraynodes.push(newnodev);
                          var newlinkt={"source":newtargetv,"target":idfact};
                          arraylinks.push(newlinkt);

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

                    
                    
                    /*arraylinks.push(newlinkr);
                    arraynodes.push(newnoder);
                    arraylinks.push(newlinka);
                    arraynodes.push(newnodea);*/
                                  
                 
                  }
                  localStorage.setItem("someVarKey", cve);
                  localStorage.setItem('sendalert',2);
                });
            }
          });
          
          arraynodes=graph["nodes"]; 
          arraylinks=graph["links"];    
                     
        }
        else{
          localStorage.setItem('sendalert',2);
        }
      }
      else{
        continue;
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