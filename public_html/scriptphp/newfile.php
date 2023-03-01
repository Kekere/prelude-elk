<?php
//exec_shell("rm general.P");
$rulesinit = '/home/mulval/kb/interaction_rules.P';
$rules = 'running_rules.P';
$address = $_POST['address'];
$port = $_POST['port'];
$protocol = $_POST['protocol'];
$cve = $_POST['cve'];
$product = $_POST['product'];
$username = $_POST['username'];
//$address = '157.159.68.125';
// Ouvre un fichier pour lire un contenu existant
$current = file_get_contents($rulesinit);
// Ajoute une personne
$current .= "\nderived(gainsPrivileges(_host)).
:- table gainsPrivileges/1.\n
  interaction_rule(
    (gainsPrivileges('".$address ."') :-
        networkServiceInfo('".$address ."',".$product.",".$protocol.",'".$port."',".$username."),
        vulExists('".$address ."','".$cve."',".$product.",remoteExploit,privEscalation),	
        netAccess('".$address ."', ".$protocol.", '".$port."')),
    rule_desc('Gain Privileges',
    1.0)).";
// Écrit le résultat dans le fichier
//file_put_contents($rules, $current);
//echo file_get_contents($rules);
echo $current;
$myFile = "general.P";
$fh = fopen($myFile, 'w') or die("can't open file");
fwrite($fh, $current);
fclose($fh);
?>