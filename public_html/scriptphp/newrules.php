<?php
$file = '../uploads/ifipsec.P';
$rulesinit = 'general.P';
$rules = 'running_rules.P';
$address = $_POST['address'];
$fact = $_POST['fact'];
$rule = $_POST['rule'];
//$address = '157.159.68.125';
// Ouvre un fichier pour lire un contenu existant
$current = file_get_contents($rulesinit);
//echo $current;
// Ajoute une personne
$current .= "\nderived(".$fact."(_host)).
:- table shutdown/1.\n
interaction_rule(
  (physicalDamage(_bus) :-
 shutdown('".$address."')),
  rule_desc('Physical damage',
  0.5)).\n
interaction_rule(
  (".$fact."(_host) :-
  execCode('".$address."', _user)),
  ".$rule.").";
// Écrit le résultat dans le fichier
//file_put_contents($rules, $current);
//echo file_get_contents($rules);
$myFile = "general.P";
$fh = fopen($myFile, 'w') or die("can't open file");
fwrite($fh, $current);
fclose($fh);
?>