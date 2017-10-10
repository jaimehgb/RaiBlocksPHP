<?php

if (!extension_loaded("libsodium")) exit(0);

include "../autoload.php";

$salt = Salt::instance();

$keys = crypto_sign_keypair();

$sodium_sk = crypto_sign_secretkey($keys);
$sodium_pk = crypto_sign_publickey($keys);

$sk = FieldElement::fromString($sodium_sk);
$pk = FieldElement::fromString($sodium_pk);

$msg = "Lorem ipsum dolor sit amet, consectetur adipiscing elit.";

$sodium_sm = crypto_sign($msg, $sodium_sk);

$signed_msg = $salt->crypto_sign($msg, strlen($msg), $sk);

if (sodium_memcmp($sodium_sm, $signed_msg->toString()) === 0) {
	echo $sodium_sm."\n";
	echo $signed_msg->toString()."\n\n";
} else {
	echo "invalid signed message";
	exit(0);
} 

$sodium_open_msg = crypto_sign_open($sodium_sm, $sodium_pk);

$plaintext = $salt->crypto_sign_open($signed_msg, count($signed_msg), $pk);

if ($plaintext === false) {
	echo "debug time...";
	exit(0);
}

if (sodium_memcmp($sodium_open_msg, $plaintext->toString()) === 0) {
	echo $sodium_open_msg."\n";
	echo $plaintext->toString()."\n";
}

echo "\nmemory peak: ".memory_get_peak_usage(true)."\n";
