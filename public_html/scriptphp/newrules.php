<?php
$file = '../uploads/ifipsec.P';
$rules = '/home/mulval/kb/interaction_rules.P';
//$address = $_POST['address'];
$address = '157.159.68.125';
// Ouvre un fichier pour lire un contenu existant
$current = file_get_contents($rules);
// Ajoute une personne
$current .= "\nderived(shutdown(_host)).
:- table shutdown/1.\n
interaction_rule(
  (physicalDamage(_bus) :-
 shutdown(_host)),
  rule_desc('Physical damage',
  0.5)).\n
interaction_rule(
  (shutdown(_host) :-
  execCode('".$address."', _user)),
  rule_desc('Shutdown',
  0.5)).";
// Écrit le résultat dans le fichier
file_put_contents($rules, $current);
$XSBHOME="/home/XSB";
$MulvalRoot="/home/mulval";
// reception du fichier issu de la conversion xmlToJson depuis le client en JS


$output = shell_exec("export XSBHOME=".$XSBHOME." && export MULVALROOT=".$MulvalRoot." && export PATH=\$PATH:\$MULVALROOT/utils && export PATH=\$PATH:\$MULVALROOT/bin && PATH=\$PATH:\$XSBHOME/bin && graph_gen.sh ".$file." -l");
echo $output;
?>