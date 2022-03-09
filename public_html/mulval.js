

  //console.log(jsonfinal);

  // nom du fichier qui sera qui sera généré par le serveur php

  var jsonfile="mulval_generated_json.json";

  // conversion du fichier AttackGraph généré par mulval en Objet Json
  jsonfinal=convertxmltojson("AttackGraph.xml");
  
  // ecriture du resultat de la conversion dans le local storage

  localStorage.setItem('myjson',JSON.stringify(jsonfinal,null,4));
      
  var jsonobj={"json":JSON.stringify(jsonfinal,null,4)};


  /* transfert du resultat de la convertion au serveur PHP pour l'écriture
  dans un fichier json "mulval_generated_json.json" qui sera utilisé comme paramètre de la fonction generategraph
  */
$.ajax({
    url:"mulval.php",
    data:jsonobj,
    datatype:"json",
    type:"POST",
    success: function(response){
      
      // après la creation du fichier JSON en php on génère le Graph
      generateGraph(jsonfile); 
      
    },
    failure:function(response){
      console.log("erreur");
    }
  });