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
	
	public static function checkSig($msg, $sig, $account)
	{
		$sig = Uint::fromHex($sig)->toUint8();
		$msg = Uint::fromHex($msg)->toUint8();
		$pk = Uint::fromHex(self::keyFromAccount($account))->toUint8();
		
		$sm = new SplFixedArray(64 + count($msg));
		$m = new SplFixedArray(64 + count($msg));
		for ($i = 0; $i < 64; $i++) $sm[$i] = $sig[$i];
		for ($i = 0; $i < count($msg); $i++) $sm[$i+64] = $msg[$i];
		return Salt::crypto_sign_open2($m, $sm, count($sm), $pk);
	}
	
	public static function sign($sk, $msg)
	{
		$salt = Salt::instance();
		$sk = FieldElement::fromArray(Uint::fromHex($sk)->toUint8());
		$pk = Salt::crypto_sign_public_from_secret_key($sk);
		$sk->setSize(64);
		$sk->copy($pk, 32, 32);
		$msg = Uint::fromHex($msg)->toUint8();
		$sm = $salt->crypto_sign($msg, count($msg), $sk);
		
		$signature = [];
		for($i = 0; $i < 64; $i++)
		    $signature[$i] = $sm[$i];
		return Uint::fromUint8Array($signature)->toHexString();
	}
	
	public static function newKeyPair()
	{
		$salt = Salt::instance();
		$keys = $salt->crypto_sign_keypair();
		$keys[0] = Uint::fromUint8Array(array_slice($keys[0]->toArray(), 0, 32))->toHexString();
		$keys[1] = Uint::fromUint8Array($keys[1])->toHexString();
		return $keys;
	}
	
	public static function keyFromAccount($acc)
	{
		if( (strpos($acc, 'xrb_1') === 0 || strpos($acc, 'xrb_3') === 0) && strlen($acc) == 64)
		{
			$crop = substr($acc, 4, 64);
			if(preg_match('/^[13456789abcdefghijkmnopqrstuwxyz]+$/', $crop))
			{
				$aux = Uint::fromString(substr($crop, 0, 52))->toUint4()->toArray();
				array_shift($aux);
				$key_uint4 = $aux;
				$hash_uint8 = Uint::fromString(substr($crop, 52, 60))->toUint8()->toArray();
				$key_uint8 = Uint::fromUint4Array($key_uint4)->toUint8();
				
				$key_hash = new SplFixedArray(64);
				$b2b = new Blake2b();
				$ctx = $b2b->init(null, 5);
				$b2b->update($ctx, $key_uint8, count($key_uint8));
				$b2b->finish($ctx, $key_hash);
				$key_hash = array_reverse(array_slice($key_hash->toArray(), 0, 5));
				
				if($hash_uint8 == $key_hash)
				{
					return Uint::fromUint4Array($key_uint4)->toHexString();
				}
			}
		}
		return false;
	}
	
	public static function accountFromKey($pk)
	{
		if(!preg_match('/[0-9A-F]{64}/i', $pk))
			throw new InvalidRaiBlocksKeyException("Key should be a 32 byte hex string");
		
		$key = Uint::fromHex($pk);
		$checksum;
		$hash = new SplFixedArray(64);
		$b2b = new Blake2b();
		$ctx = $b2b->init(null, 5);
		$b2b->update($ctx, $key->toUint8(), 32);
		$b2b->finish($ctx, $hash);
		$hash = Uint::fromUint8Array(array_slice($hash->toArray(), 0, 5))->reverse();
		
		$checksum = $hash->toString();
		$c_account = Uint::fromHex('0' . $pk)->toString();
		return 'xrb_' . $c_account . $checksum;
	}
}



