<?php
//ini_set('display_errors', 1);
//$command = escapeshellcmd('../scriptpython/query.py');
//$output = shell_exec($command);
$cveid = $_POST['cveid'];
$prod = $_POST['prod'];
//$cveid="CVE-2012-0152";
//$prod="windows";
//$output=shell_exec("python3 ../scriptpython/querypost.py");
$output = shell_exec("python3 ../scriptpython/querypost.py $cveid $prod");

//shell_exec("rm ../postcon.json");
$boolarr=json_decode(json_encode(str_replace("'",'"',$output)));
if(strlen($boolarr)>3){
    echo $output;
    $file='../postcon.json';
    $fh = fopen($file, 'w') or die("can't open file");
    $stringData = json_decode(json_encode(str_replace("'",'"',$output)));
    fwrite($fh, $stringData);
    fclose($fh);
}

?>
