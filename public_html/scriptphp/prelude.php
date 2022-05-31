<?php

use Elasticsearch\ClientBuilder;

require '../vendor/autoload.php';

$hosts = [
    'http://elastic:prelude@172.31.0.4:9200' 
];


$client = ClientBuilder::create()
                    ->setHosts($hosts)
                    ->build();
$json = '{
  "sort" : {
    "_timestamp" : { "order" : "desc" }
  },
  "from" : 0, "size" : 10
}';

$params = [
  'index' => 'prelude09',
  'type' => '_doc',
  'body' => [
    'query' => [
       'match' => [
           'text' => 'Eventscan'
       ]
    ]
  ] 
];
$params2=[
  'index' => 'source',
  'body' => [
    'sort' => [
      '@timestamp' => [
	  'order' => "desc"
	]
    ]  
  ]
];
$params3=[
  'index' => 'target',
  'body' => [
    'sort' => [
      '@timestamp' => [
	  'order' => "desc"
	]
    ]  
  ] 
];

$response = $client->search($params3);
$responsesource = $client->search($params2);
#print_r($response);
$address=$response['hits']['hits'][0]['_source']['address'];
$protocol=$response['hits']['hits'][0]['_source']['iana_protocol_name'];
$severity=$response['hits']['hits'][0]['_source']['severity'];
$port=$response['hits']['hits'][0]['_source']['port'];
$addresssource=$responsesource['hits']['hits'][0]['_source']['address'];
$protocolsource=$responsesource['hits']['hits'][0]['_source']['iana_protocol_name'];
//$severitysource=$responsesource['hits']['hits'][0]['_source']['severity'];
$portsource=$responsesource['hits']['hits'][0]['_source']['port'];
$timestamp=$response['hits']['hits'][0]['_source']['createtime'];

$advert = array(
  'address' => $address,
  'protocol' => $protocol,
  'severity' => $severity,
  'port' => $port,
  'addresssource' => $addresssource,
  'protocolsource' => $protocolsource,
  //'severitysource' => $severitysource,
  'portsource' => $portsource,
  'timestamp' => $timestamp
);
echo json_encode($advert);
?>
