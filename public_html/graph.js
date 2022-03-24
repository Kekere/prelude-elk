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
  //var severitysource=document.getElementById("your-hidden-severitysource").value;
  //console.log(document.getElementById("your-hidden-jsonobj").value)
  
  var jsonfiles=document.getElementById("your-hidden-jsonlist").value.split(',');

  for (var i = 0; i < graph["nodes"].length; i++){
  var hacl=graph["nodes"][i]["label"].indexOf("hacl");
  var net=graph["nodes"][i]["label"].indexOf("networkServiceInfo");
  var vul=graph["nodes"][i]["label"].indexOf("vulExists");
  var ch;
  //console.log(vul,graph["nodes"][i]["label"]);
  
  if(hacl==0){
    var sep=graph["nodes"][i]["label"].split(',');
    adds=sep[0].split("'")[1];
    //console.log(adds,addresssource,sep[2],protocol,parseInt(sep[3].split("):")[0]),port)
    if(adds==addresssource && sep[2]==protocol && parseInt(sep[3].split("):")[0])==port){
      ch=1
      
    }
    
  }
  if(net==0){
    var sep=graph["nodes"][i]["label"].split(',');
    add=sep[0].split("'")[1];
    addsource=sep[0].split("'")[1];
    if(add==address && sep[2]==protocol && parseInt(sep[3].split("):")[0])==port){
      val=1;
      

      
      product=sep[1].split("'")[0];
      //console.log(product)
      
    }
    else{
      if(ch==1){
        product=sep[1].split("'")[0];
        //console.log(product);
        val=1;
        console.log("condition fonctionne pour enrichissement");
      }
      else{
        if(ch==1){
          product=sep[1].split("'")[0];
          //console.log(product);
          //console.log("condition fonctionne pour enrichissement");
        }
        
        /*if(addsource==addresssource && sep[2]==protocolsource && parseInt(sep[3].split("):")[0])==portsource){
           val=1;
           add=addsource;
           protocol=protocolsource;
           port=portsource;
           product=sep[1].split("'")[0];
           console.log(portsource);
        
        }*/
      }
    }
    
  }
  if(vul==0 && val==1){

      var sep=graph["nodes"][i]["label"].split(',');
      idvul=graph["nodes"][i]["id"];
      //console.log(idvul);
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
        var jsonpost={};
        //var arraypost=[];
        //console.log(vul,graph["nodes"][i]["label"]);
        /*$.getJSON("vdo/CVE-2019-1181.json", function(data){
          precondition=data["Vulnerability"]["hasScenario"][0]["barrier"][0]["barrierType"].split(':')[4];
          for(var e=0; e<data["Vulnerability"]["hasScenario"].length; e++){
            for(var b=0; b<data["Vulnerability"]["hasScenario"][e]["affectsProduct"]["hasEnumeration"]["values"].length; b++){
              prod=data["Vulnerability"]["hasScenario"][e]["affectsProduct"]["hasEnumeration"]["values"][b].split(':')[4];
              products.push(prod);
              
            }
          }
           
        })*/
        function namefile(n){
          $.getJSON("vdo/"+n, function(data){
            //console.log(n)
            precondition=data["Vulnerability"]["hasScenario"][0]["barrier"][0]["barrierType"].split(':')[4];
            newcve=n.split('.')[0];
            //console.log(precondition)
            //console.log(newcve);
            for(var e=0; e<data["Vulnerability"]["hasScenario"].length; e++){
              for(var b=0; b<data["Vulnerability"]["hasScenario"][e]["affectsProduct"]["hasEnumeration"]["values"].length; b++){
                prod=data["Vulnerability"]["hasScenario"][e]["affectsProduct"]["hasEnumeration"]["values"][b].split(':')[4];
                products.push(prod);
                
              }
            }
            //console.log(products);
            products=[];
          })
          
        }
        
        $.getJSON("vdo/"+cve+".json", function(json) {
          //console.log(localStorage.getItem("someVarKey"))
          if(json["Vulnerability"]["hasIdentity"][0]["value"]==cve && localStorage.getItem('someVarKey')!=cve){
            
            for(var e=0; e<json["Vulnerability"]["hasScenario"].length; e++){
              for(var b=0; b<json["Vulnerability"]["hasScenario"][e]["affectsProduct"]["hasEnumeration"]["values"].length; b++){
                prod=json["Vulnerability"]["hasScenario"][e]["affectsProduct"]["hasEnumeration"]["values"][b].split(':')[4];
                if(prod==product){
                  valprod=1;
                }
              }
              
              for(var o=0; o<json["Vulnerability"]["hasScenario"][e]["hasAction"].length; o++){
                //console.log(json["Vulnerability"]["hasScenario"][e]["hasAction"][o])
                //console.log(json["Vulnerability"]["hasScenario"][e]["hasAction"][1]["resultsInImpact"][0]['hasLogicalImpact'])
                if(json["Vulnerability"]["hasScenario"][e]["hasAction"][o]["resultsInImpact"].length==1){
                  for(var t=0; t<json["Vulnerability"]["hasScenario"][e]["hasAction"][o]["resultsInImpact"].length; t++){
                    if(o==1){
                      //console.log(json["Vulnerability"]["hasScenario"][e]["hasAction"][o]["resultsInImpact"][t]["hasLogicalImpact"])
                      check=json["Vulnerability"]["hasScenario"][e]["hasAction"][o]["resultsInImpact"][t]["hasLogicalImpact"]
                      //console.log(check, seps)
                      var isEvery = seps.every(item => check.toLowerCase().includes(item.toLowerCase()));
                      
                      
                      if(isEvery==true && valprod!=0){
                        logicalimpact=json["Vulnerability"]["hasScenario"][e]["hasAction"][1]["resultsInImpact"][t]["hasLogicalImpact"].split("::").slice(-1)[0];
                        //console.log(graph["links"]);
                        //console.log(graph["nodes"])
                        arraylinks=graph["links"];
                        
                        for(var p=0; p<arraylinks.length; p++){
                          if(idvul==arraylinks[p]["source"]){
                            for(var m=0; m<arraylinks.length; m++){
                              if(arraylinks[p]["target"]==arraylinks[m]["source"]){
                                //console.log(arraylinks[p]["target"],arraylinks[m]["source"]);
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
                                  
                                  //console.log(jsonfiles[y])
                             
                                  var n=jsonfiles[y];
                                  $.getJSON("vdo/"+n, function(data){
                                    precondition=data["Vulnerability"]["hasScenario"][0]["barrier"][0]["barrierType"].split(':')[4];
                                    newcve=data["Vulnerability"]["hasIdentity"][0]["value"];
                                    for(var u=0; u<data["Vulnerability"]["hasScenario"].length; u++){
                                      for(var h=0; h<data["Vulnerability"]["hasScenario"][u]["affectsProduct"]["hasEnumeration"]["values"].length; h++){
                                        prod=data["Vulnerability"]["hasScenario"][u]["affectsProduct"]["hasEnumeration"]["values"][h].split(':')[4];
                                        products.push(prod);
                                        
                                      }
                                    }
                                    
                                    if(weaknesses.includes(precondition) && products.includes(product)){
                                      
                                      newtarget=parseInt(arraynodes.length+1)
                                      newlinkr={"source":newtargeta,"target":newtarget};
                                      newnoder={id: newtarget, group: 4, label: "canExploit"+" ("+newcve+"):0"}
                                      arraylinks.push(newlinkr);
                                      arraynodes.push(newnoder);
                                    }
                                    newnoder={};
                                    newlinkr={};
                                    newnodea={};
                                    newlinka={};
                                    jsonfinal={"nodes":arraynodes,"links":arraylinks};
                                    //console.log(jsonfinal);
                                    localStorage.setItem('myjson',JSON.stringify(jsonfinal,null,4));
                                    obj=JSON.parse(localStorage.getItem('myjson')); 
                                    //console.log(obj)
                                    //$("svg").empty();
                                    generateGraph("output.json");                               
                                  })
                                                   
                                  
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
                  //console.log(jsonfinal);
                  localStorage.setItem('myjson',JSON.stringify(jsonfinal,null,4));
                  obj=JSON.parse(localStorage.getItem('myjson')); 
                  //console.log(obj)
                  //$("svg").empty();
                  generateGraph("output.json");
                }
                
                else{
                  //console.log(json["Vulnerability"]["hasScenario"][e]["hasAction"][o]["resultsInImpact"])
                  for(var r=0; r<json["Vulnerability"]["hasScenario"][e]["hasAction"][o]["resultsInImpact"].length; r++){
                    check=json["Vulnerability"]["hasScenario"][e]["hasAction"][o]["resultsInImpact"][r]["hasLogicalImpact"]
                    var isEvery = seps.every(item => check.toLowerCase().includes(item.toLowerCase()));
                    if(isEvery==true && valprod!=0){
                      logicalimpact=json["Vulnerability"]["hasScenario"][e]["hasAction"][o]["resultsInImpact"][r]["hasLogicalImpact"].split("::").slice(-1)[0];
                      //console.log(graph["links"]);
                      //console.log(graph["nodes"])
                      arraylinks=graph["links"];
                      
                      for(var p=0; p<arraylinks.length; p++){
                        if(idvul==arraylinks[p]["source"]){
                          for(var m=0; m<arraylinks.length; m++){
                            if(arraylinks[p]["target"]==arraylinks[m]["source"]){
                              //console.log(p,m);
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
                  //console.log(jsonfinal);
                  localStorage.setItem('myjson',JSON.stringify(jsonfinal,null,4));
                  obj=JSON.parse(localStorage.getItem('myjson')); 
                  //console.log(obj)
                  //$("svg").empty();
                  generateGraph("output.json");
                  
                }
              }
            }
            localStorage.setItem("someVarKey", cve);
          }
        });
      }
  } 
  }
}
  
document.getElementById("home").onclick = function() {
  localStorage.setItem("someVarKey","");
  var link = document.getElementById("home");
  link.setAttribute("href", "index.html");
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
