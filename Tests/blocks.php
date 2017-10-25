<?php


require dirname(__DIR__) . '/RaiBlocksBlock.php';

$block = new RaiBlocksBlock();

$block->send(
	$previous='1967EA3553D6CEA90987D6C2CD5F101278823F497DA5527A6E1C0F2F3E5BF801',
	$destination='xrb_3wm37qz19zhei7nzscjcopbrbnnachs4p1gnwo5oroi3qonw6inwgoeuufdp',
	$balance="1383752549851325167221744836530526348"
);

$block->build();
echo $block->getHash()->toHexString(); // F927A61F6CB97A54166A6532C3BCCCF3D184C7B62301D7396470E6ACE18C4248
echo "\n";

$block->receive('DC04354B1C20C0DC0D14339B50F428B95481DFE627507FE64862BAE8FA2661B2', 'DC1E2B3F7C6BBE67990EF8F31E288F47EDA9B82893CA869E25955182A0E26B4A');
$block->build();
echo $block->getHash()->toHexString(); // 7D3844CD04DF96022113D0E1C4785D565CEF2C9629A96868C3C9876C90BFF92A
echo "\n";

$block->open(
	$source='BE548A457F28A42119FB22373303690DAB5F40811E4E87643A15267827D6C138',
	$account='xrb_3pg6xswkroybxydyzaxybb1h531sx34omiu7an9t9jy19f9mca7a36s7by5e',
	$representative='xrb_1anrzcuwe64rwxzcco8dkhpyxpi8kd7zsjc1oeimpc3ppca4mrjtwnqposrs'
);
$block->build();
echo $block->getHash()->toHexString(); // 361B2201C899AF56D3901CCEF11B1CBD728CD5563721124F3E944AED277D2425	
echo "\n";

$block->change(
	$previous='ECCF08BBB0556D8527CC739C01DDC466415300B781B5988E8FE9A62D765FDD5C',
	$representative='xrb_1nkquu5dnehkn7fw69ksqh37fkrjc7oao4rrc3f37m868tohxizywzagjc89'
);
$block->build();
echo $block->getHash()->toHexString(); // FF14307F67B85C8F4EE903447E24818618CEA7B9C45DCCF6819F8F129CE63DB1	
echo "\n";


// json serialization

$block->send(
	$previous='4270F4FB3A820FE81827065F967A9589DF5CA860443F812D21ECE964AC359E05',
	$destination='xrb_1111111111111111111111111111111111111111111111111111hifc8npp',
	$balance=hexToDec("000000041C06DF91D202B70A40000011")
);
$block->build();

$block->setAccount('xrb_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuohr3');
$block->setWork("7202df8a7c380578");
$block->setSignature("047115CB577AC78F5C66AD79BBF47540DE97A441456004190F22025FE4255285F57010D962601AE64C266C98FA22973DD95AC62309634940B727AC69F0C86D03");

print_r($block->getJSONRepresentation());


