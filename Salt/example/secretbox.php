<?php

include "../autoload.php";

$key = Salt::randombytes(32);
$nonce = Salt::randombytes(24);

$msg = 'The Salt::secretbox() function encrypts and authenticates a message using secret key and a nonce.';

$chipertext = Salt::secretbox($msg, $nonce, $key);

$plaintext = Salt::secretbox_open($chipertext, $nonce, $key);

if (!$plaintext) {
	echo 'This is a bug';
} else {
	echo $plaintext->toString();
}

echo "\n";
