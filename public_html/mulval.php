
<?php


// Variable de définition des chemin MulvalRoot et XSB
// Modifier les variables en fonction des chemins MulvalRoot et XSB selon votre serveur


$XsbRoot="/home/XSB/bin";
$MulvalRoot="/home/mulval";





// reception du fichier issu de la conversion xmlToJson depuis le client en JS

if (isset($_POST['json'])){

   // code de generation du fichier Json
   
   file_put_contents("mulval_generated_json.json", $_POST['json']);


}


else {

// Entree dans le code d'upload du fichier

$dir='./uploads';
if( !file_exists($dir) ) 
{
   mkdir($dir, 0777, true);
}
else
{
    //The directory already exists
}

$uploaded_filename = "uploads/" . $_FILES['file']['name'];

if( move_uploaded_file($_FILES['file']['tmp_name'], $uploaded_filename) )

{


   //echo $uploaded_filename; 

    $output = shell_exec("export PATH=\$PATH:".$XsbRoot." && export MULVALROOT=".$MulvalRoot." && export PATH=\$PATH:\$MULVALROOT/utils && export PATH=\$PATH:\$MULVALROOT/bin && graph_gen.sh $uploaded_filename -p -v");

   //echo $output;

// redirection vers la page de génération
   sleep(2);
   header("location:graph.html");

}
else
{
    echo "Something went wrong uploading the file";
}


}







?>

