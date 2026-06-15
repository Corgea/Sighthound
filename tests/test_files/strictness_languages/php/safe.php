<?php

$safe_cmd = escapeshellarg($_GET["cmd"]);
system($safe_cmd);

$safe_id = intval($_POST["id"]);
$db->query("SELECT * FROM users WHERE id = $safe_id");
