<?php
 
$words = ['apple', 'radar', 'mango', 'civic', 'banana'];
 
$pal_index = 0;
$last_pal = 0;
foreach($words as $word) {
  if($word == strrev($word)) {
    $last_pal = $pal_index;
  }
  echo '<p>'.ucfirst($word).'</p>';
  $pal_index += 1;
}
?>
<script>
<?php
echo 'let p_el = document.querySelectorAll("p")['.$last_pal.']';
?>
let red = Math.round(p_el.getBoundingClientRect().top)%256;
let green = Math.round(p_el.getBoundingClientRect().right)%256;
p_el.style.color =  "rgb(" + red + ", " + green + ", 0)";
</script>
