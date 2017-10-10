<?php

include '../autoload.php';

// testVectors from http://tools.ietf.org/html/draft-agl-tls-chacha20poly1305-04#page-11
$testVectors = array(
	array(
		'0000000000000000000000000000000000000000000000000000000000000000',
		'746869732069732033322d62797465206b657920666f7220506f6c7931333035',
		'49ec78090e481ec6c26b33b91ccc0307'
	),
	array(
		'48656c6c6f20776f726c6421',
		'746869732069732033322d62797465206b657920666f7220506f6c7931333035',
		'a6f745008f81c916a20dcc74eef2b2f0'
	)
);

for ($i = 0; $i < count($testVectors); $i++) {
	$msg = FieldElement::fromHex($testVectors[$i][0]);
	$key = FieldElement::fromHex($testVectors[$i][1]);
	$mac = FieldElement::fromHex($testVectors[$i][2]);

	if (!Salt::onetimeauth_verify($mac, $msg, $key)) {
		echo "error: ".$i."\n";
	} else {
		echo $i." OK\n";
	}
}
