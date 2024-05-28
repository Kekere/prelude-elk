<?php
$xml = simplexml_load_string("AttackGraph.xml");
$json = json_encode($xml);
$array = json_decode($json,TRUE);
shell_exec("rm ../mulval_generated_json.json");
$fh = fopen("../mulval_generated_json.json", 'w') or die("can't open file");
fwrite($fh, $array);
fclose($fh)
?> 