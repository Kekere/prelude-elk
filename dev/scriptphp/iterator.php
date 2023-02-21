<?php
$dir = "../vdo/";
$push=array();

// Sort in ascending order - this is default
$a = array_diff(scandir($dir), array('.', '..','schema'));

// Sort in descending order
$b = scandir($dir,1);

foreach($a as $key => $value) {
    $push[]=$value;
  }
echo json_encode($push);
?>