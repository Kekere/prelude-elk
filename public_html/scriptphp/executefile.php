<?php
$file = '../uploads/ifipsec.P';
$rulesinit = 'general.P';
$rules = 'running_rules.P';
$address = $_POST['address'];
$port = $_POST['port'];
$protocol = $_POST['protocol'];
$cve = $_POST['cve'];
$product = $_POST['product'];
$username = $_POST['username'];
//$address = '157.159.68.125';
//$username = 'olivia';
//$product = 'windows';
//$cve = 'CVE-2017-0143';
//$address = '157.159.68.125';
// Ouvre un fichier pour lire un contenu existant
$current = file_get_contents($rulesinit);
//echo $current;
// Ajoute une personne
$current .= "\n
  interaction_rule(
    (execCode('".$address ."', ".$username.") :-
        vulExists('".$address ."','".$cve."',".$product.",remoteExploit,privEscalation),		
        gainsPrivileges('".$address ."'),
        networkServiceInfo('".$address ."',".$product.",".$protocol.",_,".$username.")),
    rule_desc('remote exploit of a server program',
    1.0)).";
// Écrit le résultat dans le fichier
//file_put_contents($rules, $current);
//echo file_get_contents($rules);
$myFile = "general.P";
$fh = fopen($myFile, 'w') or die("can't open file");
fwrite($fh, $current);
fclose($fh);
?>