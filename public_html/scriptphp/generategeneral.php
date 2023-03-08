<?php
//exec_shell("rm general.P");
$rulesinit = '/home/mulval/kb/interaction_rules.P';
$rules = 'running_rules.P';
//$address = '157.159.68.125';
// Ouvre un fichier pour lire un contenu existant
$current = file_get_contents($rulesinit);
echo $current;
$myFile = "general.P";
$fh = fopen($myFile, 'w') or die("can't open file");
fwrite($fh, $current);
fclose($fh);
?>