<?php

include '../autoload.php';

// testVectors from http://tools.ietf.org/html/draft-agl-tls-chacha20poly1305-04#page-11
$testVectors = array(
	'4290bcb154173531f314af57f3be3b5006da371ece272afa1b5dbdd1100a1007',
	'86d09974840bded2a5ca',
	'cd7cf67be39c794a',
	'87e229d4500845a079c0',
	'e3e446f7ede9a19b62a4677dabf4e3d24b876bb284753896e1d6',
);

function printDiff($a, $b) {
	printf("want:\n");
		for ($i = 0; $i < count($a); $i++) printf("%02x,", $a[$i]); printf("\n");
	printf("got :\n");
		for ($i = 0; $i < count($b); $i++) printf("%02x,", $b[$i]); printf("\n");
	printf("diff:\n");
		for ($i = 0; $i < count($a); $i++) {
			if ($a[$i] ^ $b[$i]) {
				printf("%02x,", $a[$i] ^ $b[$i]);
			} else {
				printf("  ,");
			}
		}
	printf("\n\n");
}

$key      = FieldElement::fromHex($testVectors[0]);
$input    = FieldElement::fromHex($testVectors[1]);
$nonce    = FieldElement::fromHex($testVectors[2]);
$ad       = FieldElement::fromHex($testVectors[3]);
$expected = FieldElement::fromHex($testVectors[4]);

$ciphertext = Salt::encrypt($input, $ad, $nonce, $key);

if (!Salt::equal($expected, $ciphertext)) {
	echo "encryption error:\n";
	printDiff($expected, $ciphertext);
} else {
	echo "encryption OK\n";
}

$plaintext = Salt::decrypt($ciphertext, $ad, $nonce, $key);

if (!Salt::equal($input, $plaintext)) {
	echo "decryption error:\n";
	printDiff($input, $plaintext);
} else {
	echo "decryption OK\n";
}
