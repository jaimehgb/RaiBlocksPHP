<?php

include "../autoload.php";

// alice generate key pair
$alice = Salt::box_keypair();

$alice_privatekey = $alice[0];
$alice_publickey = $alice[1];

// bob generate key pair
$bob = Salt::box_keypair();

$bob_privatekey = $bob[0];
$bob_publickey = $bob[1];

$msg = 'Lorem ipsum dolor sit amet, consectetur adipiscing elit.';

// alice generate 24 byte nonce
$nonce = Salt::randombytes(24);

// alice encrypt the message using her private key, bob publickey and a nonce
$chipertext = Salt::box($msg, $alice_privatekey, $bob_publickey, $nonce);

// bob decrypt the chipertext from alice using his private key, alice public key and
// a nonce received from alice
$the_message = Salt::box_open($chipertext, $bob_privatekey, $alice_publickey, $nonce);

if (!$the_message) {
	echo 'This is a bug';
} else {
	// bob read the message
	echo $the_message->toString();
}

echo "\n";
