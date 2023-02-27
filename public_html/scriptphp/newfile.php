
<?php
$file = 'nessus.P';
// Ouvre un fichier pour lire un contenu existant
$current = file_get_contents($file);
// Ajoute une personne
//$current .= "neededPrivileges('157.159.68.97', 'admin').
//successExploit('157.159.68.97', 'CVE-2012-0152').\n";
// Écrit le résultat dans le fichier
$current = $_POST['fact'];;
file_put_contents($file, $current);
$XSBHOME="/home/XSB";
$MulvalRoot="/home/mulval";
// reception du fichier issu de la conversion xmlToJson depuis le client en JS


$output = shell_exec("export XSBHOME=".$XSBHOME." && export MULVALROOT=".$MulvalRoot." && export PATH=\$PATH:\$MULVALROOT/utils && export PATH=\$PATH:\$MULVALROOT/bin && PATH=\$PATH:\$XSBHOME/bin && graph_gen.sh".$file." -l");
echo $output;
?>
