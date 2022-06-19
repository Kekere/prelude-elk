var token;
var jsonobj;
document.getElementById("generate-graph").onclick = function() {
  //console.log(localStorage.getItem('myjson'));
  if (token==1){
    var link = document.getElementById("generate-graph");
    link.setAttribute("href", "./graph.html");
    return true;
  }
  else{
    return false;
  }
  
}
document.getElementById("countermeasures").onclick = function() {
  //console.log(localStorage.getItem('myjson'));
  var link = document.getElementById("countermeasures");
  link.setAttribute("href", "RORI/index.html");
  
}
/*document.getElementById("home").onclick = function() {
  var link = document.getElementById("home");
  link.setAttribute("href", "index.html");
  return true;
}*/
function generateGraph(objjson){
  // set the dimensions and margins of the graph

  var svg = d3.select("#svg1").attr("viewBox", "0,0,150,400")
  .call(d3.zoom().on("zoom", function () {
    svg.attr("transform", d3.event.transform)
 })).insert('#svg1:g', ':first-child'),
      width = +svg.attr("width"),
      height = +svg.attr("height");

        
  svg.append('defs').append('marker')
      .attrs({'id':'arrowhead',
                'viewBox':'-0 -5 5 10',
                'refX':13,
                'refY':0,
                'orient':'auto',
                'markerWidth':8,
                'markerHeight':8,
                'xoverflow':'visible'})
            .append('svg:path')
            .attr('d', 'M 0,-5 L 10 ,0 L 0,5')
            .attr('fill', '#999')
            .style('stroke','none');
  
  var color = ["#32CD32","#FFD700","#FFA500","#FF4500","#b01ac4"];

  var simulation = d3.forceSimulation()
      .force("link", d3.forceLink().id(function(d) { return d.id; }))
      .force("charge", d3.forceManyBody())
      .force("center", d3.forceCenter(width / 2, height / 2));
  d3.json(objjson, function(error, graph) {
    if (error) throw error;
    graph = JSON.parse(localStorage.getItem('myjson'))
    var link = svg.append("g")
        .attr("class", "links")
      .selectAll("line")
      .data(graph.links)
      .enter().append("line")
      .attr('marker-end','url(#arrowhead)')
        .attr("stroke-width", function(d) { return Math.sqrt(d.value); });
        
    var node = svg.append("g")
        .attr("class", "nodes")
      .selectAll("g")
      .data(graph.nodes)
      .enter().append("g")
      
    var circles = node.append("circle")
        .attr("r", 5)
        .attr("fill", function(d) { return color[d.group-1]; })
        .call(d3.drag()
            .on("start", dragstarted)
            .on("drag", dragged)
            .on("end", dragended));

    var lables = node.append("text")
        .text(function(d) {
          return d.id;
        })
        .attr('x', 6)
        .attr('y', 3);
    
    node.append("title")
        .text(function(d) { return d.label; });

    simulation
        .nodes(graph.nodes)
        .on("tick", ticked);

    simulation.force("link")
        .links(graph.links);

    function ticked() {
      link
          .attr("x1", function(d) { return d.source.x; })
          .attr("y1", function(d) { return d.source.y; })
          .attr("x2", function(d) { return d.target.x; })
          .attr("y2", function(d) { return d.target.y; });

      node
          .attr("transform", function(d) {
            return "translate(" + d.x + "," + d.y + ")";
          })
    }
  });
  function dragstarted(d) {
    if (!d3.event.active) simulation.alphaTarget(0.3).restart();
    d.fx = d.x;
    d.fy = d.y;
  }

  function dragged(d) {
    d.fx = d3.event.x;
    d.fy = d3.event.y;
  }

  function dragended(d) {
    if (!d3.event.active) simulation.alphaTarget(0);
    d.fx = null;
    d.fy = null;
  }
}

function convertxmltojson(xmlfile){
  token=0;
  var xhttp;
  if (window.XMLHttpRequest) { // Create an instance of XMLHttpRequest object. 
      //code for IE7+, Firefox, Chrome, Opera, Safari
      xhttp  =  new XMLHttpRequest();
  } else { // code for IE6, IE5 
      xhttp  =  new ActiveXObject("Microsoft.XMLHTTP");
  }
  xhttp.open("GET", xmlfile, false);
  xhttp.send();
  var xmlDoc = xhttp.responseXML;
  //console.log(xmlDoc);
  var sizelinks=xmlDoc.getElementsByTagName("arc").length;
  var arraylinks=[];
  var arraynodes=[]
  var arrayelements=[];
  for (var i = 0; i < sizelinks; i++) {

    var target = xmlDoc.getElementsByTagName("arc")[i].children[0].innerHTML;
    var source = xmlDoc.getElementsByTagName("arc")[i].children[1].innerHTML;
    var jsonelement={"source":parseInt(source),"target":parseInt(target)};
    arraylinks.push(jsonelement);
    
    var sourcel=arrayelements.includes(parseInt(source));
    var targel=arrayelements.includes(parseInt(target));
    if(sourcel==false){
      arrayelements.push(parseInt(source))
    }
    if(targel==false){
      arrayelements.push(parseInt(target));
    }
  }
  for (var i=0; i< arrayelements.length; i++){
    for (var y=0; y< arrayelements.length; y++){
      if(xmlDoc.getElementsByTagName('vertex')[y].getElementsByTagName("id")[0].innerHTML==arrayelements[i]){
        var nodeAttackGraph=xmlDoc.getElementsByTagName('vertex')[y];
        var test=nodeAttackGraph.getElementsByTagName("fact")[0].innerHTML.indexOf("vulExists");
        if(nodeAttackGraph.getElementsByTagName("type")[0].innerHTML=="LEAF" && test != 0){
          var group=3;
        }
        else if(nodeAttackGraph.getElementsByTagName("type")[0].innerHTML=="LEAF" && test == 0){
          var group=4;
        }
        else if(nodeAttackGraph.getElementsByTagName("type")[0].innerHTML=="AND"){
          var group=2;
        }
        else if(nodeAttackGraph.getElementsByTagName("type")[0].innerHTML=="OR"){
          var group=1;
        }
        var labels=nodeAttackGraph.getElementsByTagName("fact")[0].innerHTML+":"+nodeAttackGraph.getElementsByTagName("metric")[0].innerHTML;
        var jsonnode={"id":arrayelements[i],"group":group,"label":labels};
        arraynodes.push(jsonnode);

      }
      
    }
  }
  var jsonfinal={"nodes":arraynodes,"links":arraylinks};
  //console.log(jsonfinal)
  //$('#your-hidden-jsonobj').val(jsonfinal);
  //console.log(document.getElementById("your-hidden-jsonobj").value)
  return jsonfinal;
}

function encode( s ) {
  var out = [];
  for ( var i = 0; i < s.length; i++ ) {
      out[i] = s.charCodeAt(i);
  }
  return new Uint8Array( out );
}

var fileInput = document.getElementById('file');

fileInput.addEventListener('change', function (e) {
  var file = fileInput.files[0];

  var reader = new FileReader();
  reader.readAsText(file);
  console.log(reader.result);
	/*var file = fileInput.files[0];

        var reader = new FileReader();
        reader.readAsText(file);
        reader.onloadend = function(){
        var xmlDoc = $(reader.result);
	   
	  var sizelinks=xmlDoc[0].getElementsByTagName("arc").length;
	  var arraylinks=[];
	  var arraynodes=[];
	  var arrayelements=[];
	  for (var i = 0; i < sizelinks; i++) {

	    var target = xmlDoc[0].getElementsByTagName("arc")[i].children[0].innerHTML;
	    var source = xmlDoc[0].getElementsByTagName("arc")[i].children[1].innerHTML;
	    var jsonelement={"source":parseInt(source),"target":parseInt(target)};
	    arraylinks.push(jsonelement);
	    
	    var sourcel=arrayelements.includes(parseInt(source));
	    var targel=arrayelements.includes(parseInt(target));
	    if(sourcel==false){
	      arrayelements.push(parseInt(source))
	    }
	    if(targel==false){
	      arrayelements.push(parseInt(target));
	    }
	  }
	  for (var i=0; i< arrayelements.length; i++){
	    for (var y=0; y< arrayelements.length; y++){
	      if(xmlDoc[0].getElementsByTagName('vertex')[y].getElementsByTagName("id")[0].innerHTML==arrayelements[i]){
		var nodeAttackGraph=xmlDoc[0].getElementsByTagName('vertex')[y];
		var test=nodeAttackGraph.getElementsByTagName("fact")[0].innerHTML.indexOf("vulExists");
		
		if(nodeAttackGraph.getElementsByTagName("type")[0].innerHTML=="LEAF" && test != 0){
		  var group=3;
		}
		else if(nodeAttackGraph.getElementsByTagName("type")[0].innerHTML=="LEAF" && test == 0){
		  var group=4;
		}
		else if(nodeAttackGraph.getElementsByTagName("type")[0].innerHTML=="AND"){
		  var group=2;
		}
		else if(nodeAttackGraph.getElementsByTagName("type")[0].innerHTML=="OR"){
		  var group=1;
		}
		var labels=nodeAttackGraph.getElementsByTagName("fact")[0].innerHTML+":"+nodeAttackGraph.getElementsByTagName("metric")[0].innerHTML;
		var jsonnode={"id":arrayelements[i],"group":group,"label":labels};
		arraynodes.push(jsonnode);

	      }
	      
	    }
	  }
	  var jsonfinal={"nodes":arraynodes,"links":arraylinks};
	 console.log(jsonfinal)*/
  
	var button = document.getElementById( 'submit' );
	button.addEventListener( 'click', function() {
    localStorage.setItem('notification', true);
    //token=1;
    
    // conversion du fichier AttackGraph généré par mulval en Objet Json
    //var newjsonfinal=convertxmltojson("AttackGraph.xml");

    // ecriture du resultat de la conversion dans le local storage

    //localStorage.setItem('myjson',JSON.stringify(newjsonfinal,null,4));
        
    //jsonobj={"json":JSON.stringify(newjsonfinal,null,4)};
    //console.log(newjsonfinal);
 
    
   
	 
	});
       // };*/
	
 });

function encode( s ) {
    var out = [];
    for ( var i = 0; i < s.length; i++ ) {
        out[i] = s.charCodeAt(i);
    }
    return new Uint8Array( out );
}



