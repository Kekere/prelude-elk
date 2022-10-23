var url = "http://dbpedia.org/sparql";
var query = [
    "PREFIX dbpedia2: <http://dbpedia.org/resource/>",
    "PREFIX Abs: <http://dbpedia.org/ontology/>",
    "SELECT ?abstract",
    "WHERE {",
       "?s dbpedia2:Civil_engineeringe\"@en;",
       "Abs:abstract ?abstract",
    "}"
   ].join(" ");
   var queryUrl = encodeURI( url+"?query="+query+"&format=json" );
   $.ajax({
       dataType: "jsonp",  
       url: queryUrl,
       success: function( _data ) {
           var results = _data.results.bindings;
           for ( var i in results ) {
               var res = results[i].abstract.value;
               console.log(res);
           }
       }
   });