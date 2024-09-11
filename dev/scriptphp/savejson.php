<?php
shell_exec("rm ../general.json");
$myFile = "../general.json";
$fh = fopen($myFile, 'w') or die("can't open file");
$stringData = $_GET["data"];
fwrite($fh, $stringData);
fclose($fh)
?> 