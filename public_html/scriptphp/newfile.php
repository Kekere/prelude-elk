
<?php
$file = '../inpker.P';
// Ouvre un fichier pour lire un contenu existant
$current = file_get_contents($file);
// Ajoute une personne
$current .= "vulExists('51.158.154.169','CVE-2017-014','windows samba',remoteExploit,privEscalation).\n";
// Écrit le résultat dans le fichier
file_put_contents($file, $current);
?>
