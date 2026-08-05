<?php
// demo PHP snippets for scanner
$id = $_GET["id"];
$result = mysqli_query($conn, "SELECT * FROM users WHERE id=".$id);
echo $_GET["q"];
system("ping ".$_GET["host"]);
$obj = unserialize($_COOKIE["data"]);
include($_GET["page"]);
