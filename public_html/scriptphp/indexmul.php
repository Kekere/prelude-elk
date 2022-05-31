<!DOCTYPE html>
<meta charset="utf-8">
<head>
</head>
<body>

  <div class="topnav">
    <a class="active" id="home" href="#home">Load XML</a>
    <a href="#graph" id="generate-graph">Generate Graph</a>
    <a href="#contact">Contermeasures</a>
    <a href="#about">About</a>
  </div>
  
  <!-- <div class="restofbody">
    <form method="post" action="" enctype="multipart/form-data" id="pform">
      <input type="file" id="file-selector" name="pfile" accept=".P">
      <button id="button" class="buttonload">Generate</button>
  </form> -->

  <form method="post" action="mulval.php" enctype="multipart/form-data" id="pform">
    <p><input type="file" name="file" id="file" required></p>
    <input type="submit" name="submit" class="submit" value="Submit">
</form>

  </div>
  





</body>
<link href="style.css" rel="stylesheet">
<script src="https://d3js.org/d3.v4.min.js"></script>
<script type="text/javascript" src="http://code.jquery.com/jquery-1.4.3.min.js" ></script>

<script src="demo.js"></script>
<script src="graph.js"></script>
<!-- <script type="text/javascript" src="upload.js" ></script> -->

