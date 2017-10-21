<?php

require '../RaiBlocks.php';

$rb = new RaiBlocks();

$keys = $rb->newKeyPair();

$sk = $keys[0];
$pk = $keys[1];

echo "Secret: " . $sk . "\n";
echo "Public: " . $pk . "\n";

echo "Public should match with: " . strtoupper(Salt::crypto_sign_public_from_secret_key(Uint::fromHex($sk)->toUint8())->toHex()) . "\n";

$rb->sign('49FF617E9074857402411B346D92174572EB5DE02CC9469C22E9681D8565E6D5', '49FF617E9074857402411B346D92174572EB5DE02CC9469C22E9681D8565E6D5');
// C1960BF84A6CCB4203C17EDFED7C7971CC866436C6B297F3312ACA1C3DA337A66CA2C6A18D92823F17E13C6243B28EF83DB6A8E026C25E848261F231F8F80A01PHP


if 
(
    $rb->checkSig(
        $msg='ECCB8CB65CD3106EDA8CE9AA893FEAD497A91BCA903890CBD7A5C59F06AB9113',
        $sig='047115CB577AC78F5C66AD79BBF47540DE97A441456004190F22025FE4255285F57010D962601AE64C266C98FA22973DD95AC62309634940B727AC69F0C86D03',
        $account='xrb_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuohr3'
    )
)
    echo "Valid Signature";
else
    echo "Invalid Signature";