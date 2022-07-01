function generateCounterGraph(objjson){
    var svg = d3.select("#svg2").attr("viewBox", "0,0,150,400")
    .call(d3.zoom().on("zoom", function () {
      svg.attr("transform", d3.event.transform)
   })).insert('#svg2:g', ':first-child'),
        width = +svg.attr("width"),
        height = +svg.attr("height");
    svg.append('defs').append('marker')
        .attrs({'id':'arrowhead',
                  'viewBox':'-0 -5 10 10',
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
    
    var color = ["#32CD32","#FFD700","#FFA500","#FF4500","#b01ac4","#520603"];
  
    var simulation = d3.forceSimulation()
        .force("link", d3.forceLink().id(function(d) { return d.id; }))
        .force("charge", d3.forceManyBody())
        .force("center", d3.forceCenter(width / 2, height / 2));
    d3.json(objjson, function(error, graph) {
      if (error) throw error;
      graph = JSON.parse(localStorage.getItem('myjsoncounter'))
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
function createContermeasureGraph(){
    graphcounter = JSON.parse(localStorage.getItem('myjson'))
    var jsonfinalcounter=convertxmltojson("../scriptphp/AttackGraph.xml");
    var arraycves=[]
    var arrayremovecves=[];
    for (var i = 0; i < graphcounter["nodes"].length; i++){
        var hacl=graphcounter["nodes"][i]["label"].indexOf("hacl");
        var net=graphcounter["nodes"][i]["label"].indexOf("networkServiceInfo");
        var vul=graphcounter["nodes"][i]["label"].indexOf("vulExists");
        

        if(vul==0){
            
            var id=graphcounter["nodes"][i]["id"]
            var cve=graphcounter["nodes"][i]["label"].split(',')[1].split("'")[1];
            var jsoncves={id:id,cve:cve};
            arraycves.push(jsoncves);
                      
        }
    }

    for (i=0; i<arraycves.length; i++){

      var action="";
      var privileges="";
      var asset="";
      var counternode={};
      var counterlink={};
      var counternoder="";
      var counterlinkr="";
      var counterarraylink=[];
      var counterarraynode=[];
      var newsource="";
      var newtarget="";
        

      $.getJSON("vdo/"+arraycves[i]["cve"]+".json", function(json) {
    
          if(!arrayremovecves.includes(json["Vulnerability"]["hasIdentity"][0]["value"])){
            arrayremovecves.push(json["Vulnerability"]["hasIdentity"][0]["value"]);
            for(var e=0; e<json["Vulnerability"]["hasScenario"].length; e++){
              counterarraynode=graphcounter["nodes"];
              counterarraylink=graphcounter["links"];
              action=json["Vulnerability"]["hasScenario"][e]["barrier"][0]["blockedByBarrier"];
              privileges=json["Vulnerability"]["hasScenario"][e]["barrier"][0]["neededPrivileges"];
              asset=json["Vulnerability"]["hasScenario"][e]["barrier"][0]["relatesToContext"];
              newsource=parseInt(counterarraynode.length+1);
              
              for(a=0; a<arraycves.length; a++){
                if(json["Vulnerability"]["hasIdentity"][0]["value"]==arraycves[a]["cve"]){
                  counterlink={"source":newsource,"target":arraycves[a]["id"]}
                  counternode={id: newsource, group: 5, label: "remove("+action+"("+privileges+" on "+asset+"))"}
                  counterarraylink.push(counterlink);
                  counterarraynode.push(counternode);
                  
                  if(counterarraynode.length!=counternode["id"]){
                    counterarraynode.length = counternode["id"];
                    
                  }
                  else{
                    console.log("ok");
                  }
                  
                }
              }
              
            }
          }
          
            
          jsonfinalcounter={"nodes":counterarraynode,"links":counterarraylink};
          
          localStorage.setItem('myjsoncounter',JSON.stringify(jsonfinalcounter,null,4));
          objcounter=JSON.parse(localStorage.getItem('myjsoncounter'));
       
      });
      }
    
    generateCounterGraph("mulval_generated_json.json");
}
var button = document.getElementById( 'downloadcounter' );
button.addEventListener( 'click', function() {
    objcounter=JSON.parse(localStorage.getItem('myjsoncounter'));
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([JSON.stringify(objcounter, null, 4)], {
      type: "text/plain"
    }));
    a.setAttribute("downloadcounter", "datacountermesure.json");
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);

});