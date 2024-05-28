<?php
$file = '../uploads/'.$_POST['filename'];
//$file = 'nessus.P';
$XSBHOME="/home/XSB";
$MulvalRoot="/home/mulval";
// reception du fichier issu de la conversion xmlToJson depuis le client en JS

$output = shell_exec("export XSBHOME=".$XSBHOME." && export MULVALROOT=".$MulvalRoot." && export PATH=\$PATH:\$MULVALROOT/utils && export PATH=\$PATH:\$MULVALROOT/bin && PATH=\$PATH:\$XSBHOME/bin && graph_gen.sh ".$file." -l -r /var/www/html/scriptphp/general.P");
echo $output;
?>