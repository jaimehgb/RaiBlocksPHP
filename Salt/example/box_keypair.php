<?php

include "../autoload.php";

$alice = Salt::box_keypair();

printf('alice secret key: ');
printf($alice[0]->toHex()."\n");

printf('alice public key: ');
printf($alice[1]->toHex()."\n");

$bob = Salt::box_keypair();

printf('bob secret key:   ');
printf($bob[0]->toHex()."\n");

printf('bob public key:   ');
printf($bob[1]->toHex()."\n");
