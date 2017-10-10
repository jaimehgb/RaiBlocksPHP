<?php

require 'Salt/autoload.php';
require_once 'util.php';
require 'RaiBlocksExceptions.php';

class RaiBlocks
{
	const MAGIC_NUMBER = "5243";   // 0x52 0x43
	const VERSION_MAX = "01";      // 0x01
	const VERSION_MIN = "01";      // 0x01
	const VERSION_USING = "01";    // 0x01
	const EXTENSIONS = "0002";     // 0x00 0x02
	const RAI_TO_RAW = "000000000000000000000000";
	const MAIN_NET_WORK_THRESHOLD = "ffffffc000000000";

	public static $blockIds = ["invalid" => 0, "not_a_block" => 1, "send" => 2, "receive" => 3, "open" => 4, "change" => 5];
	
	public function __construct()
	{
		
	}
	
	public static function keyFromAccount($acc)
	{
		if( (strpos($acc, 'xrb_1') === 0 || strpos($acc, 'xrb_3') === 0) && strlen($acc) == 64)
		{
			$crop = substr($acc, 4, 64);
			if(preg_match('/^[13456789abcdefghijkmnopqrstuwxyz]+$/', $crop))
			{
				$aux = (new Uint())->fromString(substr($crop, 0, 52))->toUint4()->toArray();
				array_shift($aux);
				$key_uint4 = $aux;
				$hash_uint8 = (new Uint())->fromString(substr($crop, 52, 60))->toUint8()->toArray();
				$key_uint8 = (new Uint())->fromUint4Array($key_uint4)->toUint8();
				
				$key_hash = new SplFixedArray(64);
				$b2b = new Blake2b();
				$ctx = $b2b->init(null, 5);
				$b2b->update($ctx, $key_uint8, count($key_uint8));
				$b2b->finish($ctx, $key_hash);
				$key_hash = array_reverse(array_slice($key_hash->toArray(), 0, 5));
				
				if($hash_uint8 == $key_hash)
				{
					return (new Uint())->fromUint4Array($key_uint4)->toHexString();
				}
			}
		}
		return false;
	}
}



