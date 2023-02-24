<?php
//ini_set('display_errors', 1);
//$command = escapeshellcmd('../scriptpython/query.py');
$output = shell_exec($command);
$cveid = $_POST['cveid'];
#$cveid="CVE-2005-1794";

//$output=shell_exec("python3 ../scriptpython/querypost.py");
$output = shell_exec("python3 ../scriptpython/queryimp.py $cveid");
echo $output;
file_put_contents("./impact.json", "");
$boolarr=json_decode(json_encode(str_replace("'",'"',$output)));
echo strlen($boolarr);
if(strlen($boolarr)>3){
    //shell_exec("rm ./postcon.json");
    echo $output;
    $file='./impact.json';
    $fh = fopen($file, 'w') or die("can't open file");
    $stringData = json_decode(json_encode(str_replace("'",'"',$output)));
    fwrite($fh, $stringData);
    fclose($fh);
}

?>
