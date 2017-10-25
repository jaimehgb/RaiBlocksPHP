<?php
require_once 'RaiBlocks.php';

class RaiBlocksBlock extends RaiBlocks
{
	
	private $type;
	private $hash;
	private $previous;
	private $balance;
	private $destination;
	
	private $source;
	
	private $work;
	private $signature;
	private $owner_account;
	
	public function build()
	{
		$hash = '';
		switch($this->type)
		{
			case 'send':
				$output = new SplFixedArray(64);
				$blake2b = new Blake2b();
				$ctx = $blake2b->init(null, 32);
				$blake2b->update($ctx, $this->previous->toUint8(), 32);
				$blake2b->update($ctx, $this->destination->toUint8(), 32);
				$blake2b->update($ctx, $this->balance->toUint8(), 16);
				$blake2b->finish($ctx, $output);
				
				$hash = new SplFixedArray(32);
				for($i = 0; $i < 32; $i++)
					$hash[$i] = $output[$i];
				$this->hash = Uint::fromUint8Array($hash);
				break;
			
			case 'receive':
				$output = new SplFixedArray(64);
				$blake2b = new Blake2b();
				$ctx = $blake2b->init(null, 32);
				$blake2b->update($ctx, $this->previous->toUint8(), 32);
				$blake2b->update($ctx, $this->source->toUint8(), 32);
				$blake2b->finish($ctx, $output);
				
				$hash = new SplFixedArray(32);
				for($i = 0; $i < 32; $i++)
					$hash[$i] = $output[$i];
				$this->hash = Uint::fromUint8Array($hash);
				break;
			
			case 'open':
				$output = new SplFixedArray(64);
				$blake2b = new Blake2b();
				$ctx = $blake2b->init(null, 32);
				$blake2b->update($ctx, $this->source->toUint8(), 32);
				$blake2b->update($ctx, $this->representative->toUint8(), 32);
				$blake2b->update($ctx, $this->account->toUint8(), 32);
				$blake2b->finish($ctx, $output);
				
				$hash = new SplFixedArray(32);
				for($i = 0; $i < 32; $i++)
					$hash[$i] = $output[$i];
				$this->hash = Uint::fromUint8Array($hash);
				break;
			
			case 'change':
				$output = new SplFixedArray(64);
				$blake2b = new Blake2b();
				$ctx = $blake2b->init(null, 32);
				$blake2b->update($ctx, $this->previous->toUint8(), 32);
				$blake2b->update($ctx, $this->representative->toUint8(), 32);
				$blake2b->finish($ctx, $output);
				
				$hash = new SplFixedArray(32);
				for($i = 0; $i < 32; $i++)
					$hash[$i] = $output[$i];
				$this->hash = Uint::fromUint8Array($hash);
				break;
			
			default:
				throw new InvalidBlockTypeException('Block type should be open/send/receive/change: ' . $type);
		}
		return $this->hash;
	}
	
	public function send($previous, $destination, $balance)
	{
		if(!preg_match('/[0-9A-F]{64}/i', $previous))
			throw new InvalidBlockHashException('Previous block hash is not valid.');
		$pk = self::keyFromAccount($destination);
		if($pk === false)
			throw new InvalidRaiBlocksAccountException('Destination account is not valid');
		if(!is_numeric($balance) || $balance < 0)
			throw new InvalidBalanceException('Balance should be an integer greater than 0');
		
		$this->previous = Uint::fromHex($previous);
		$this->destination = Uint::fromHex($pk);
		$this->balance = Uint::expandSize(16, Uint::fromDec($balance));
		$this->type = 'send';
	}
	
	public function receive($previous, $source)
	{
		if(!preg_match('/[0-9A-F]{64}/i', $previous))
			throw new InvalidBlockHashException('Previous block hash is not valid.');
		if(!preg_match('/[0-9A-F]{64}/i', $source))
			throw new InvalidBlockHashException('Source block hash is not valid.');
		
		$this->previous = Uint::fromHex($previous);
		$this->source = Uint::fromHex($source);
		$this->type = 'receive';
	}
	
	public function open($source, $account, $representative)
	{
		if(!preg_match('/[0-9A-F]{64}/i', $source))
			throw new InvalidBlockHashException('Source block hash is not valid.');
		
		$a_pk = self::keyFromAccount($account);
		$r_pk = self::keyFromAccount($representative);
		if($a_pk === false)
			throw new InvalidRaiBlocksAccountException('Open account is not valid');
		if($r_pk === false)
			throw new InvalidRaiBlocksAccountException('Representative account is not valid');
			
		
		$this->source = Uint::fromHex($source);
		$this->representative = Uint::fromHex($r_pk);
		$this->account = Uint::fromHex($a_pk);
		$this->type = 'open';
		
	}
	
	public function change($previous, $representative)
	{
		 if(!preg_match('/[0-9A-F]{64}/i', $previous))
			throw new InvalidBlockHashException('Previous block hash is not valid.');
			
		$pk = self::keyFromAccount($representative);
		
		if($pk === false)		
			throw new InvalidRaiBlocksAccountException('Representative account is not valid');
		$this->previous = Uint::fromHex($previous);
		$this->representative = Uint::fromHex($pk);
		$this->type = "change";
	}
	
	public static function checkWork($hash, $work)
	{
		if(!hex2bin($work))
			return false;
		if(strlen($work) != 16)
			return false;
		if(strlen($hash) != 64)
			return false;
		if(!hex2bin($hash))
			return false;
		
		$res = new SplFixedArray(64);
		$workBytes = Uint::fromHex($work)->toUint8();
		$hashBytes = Uint::fromHex($hash)->toUint8();
		$workBytes = array_reverse($workBytes->toArray());
		$workBytes = SplFixedArray::fromArray($workBytes);
		
		$blake2b = new Blake2b();
		$ctx = $blake2b->init(null, 8);
		$blake2b->update($ctx, $workBytes, 8);
		$blake2b->update($ctx, $hashBytes, 32);
		$blake2b->finish($ctx, $res);
		
		if($res[7] == 255)
			if($res[6] == 255)
				if($res[5] == 255)
					if($res[4] >= 192)
						return true;
		return false;
	}
	
	public function setAccount($xrb_account)
	{
		if(!RaiBlocks::keyFromAccount($xrb_account))
			throw new InvalidRaiBlocksAccountException();
		$this->owner_account = $xrb_account;
	}
	
	public function setWork($work)
	{
		if(!$this->hash)
			throw new IncompleteBlockException("Block hash is missing.");
		
		if(!self::checkWork($this->previous->toHexString(), $work))
			throw new InsufficientWorkException();
		
		$this->work = Uint::fromHex($work);
	}
	
	public function setSignature($sig)
	{
		if(!$this->owner_account)
			throw new IncompleteBlockException("To set a signature chain's account is needed.");
		if(!$this->hash)
			throw new IncompleteBlockException("Block hash is missing.");
		
		if(!RaiBlocks::checkSig($this->hash->toHexString(), $sig, $this->owner_account))
			throw new InvalidSignatureException();
		$this->signature = Uint::fromHex($sig);
	}
	
	public function getJSONRepresentation()
	{
		if(!$this->hash)
			throw new IncompleteBlockException("Block hash is missing.");
		if(!$this->signature)
			throw new IncompleteBlockException("Block signature is missing.");
		
		$json = [];
		
		if($this->type == 'open')
		{
			$json['account'] = $this->owner_account;
			$json['source'] = $this->source->toHexString();
			$json['representative'] = self::accountFromKey($this->representative->toHexString());
		}
		else
		{
			$json['previous'] = $this->previous->toHexString();
			if($this->type == 'receive')
			{
				$json['source'] = $this->source->toHexString();
			}
			else if($this->type == 'send')
			{
				$json['balance'] = $this->balance->toHexString();
				$json['destination'] = self::accountFromKey($this->destination->toHexString());
			}
			else if($this->type == 'change')
			{
				$json['representative'] = self::accountFromKey($this->representative->toHexString());
			}
		}
		$json['signature'] = $this->signature->toHexString();
		$json['work'] = $this->work ? $this->work->toHexString() : "false";
		return json_encode($json);
	}
	
	public function getHash()
	{
		return $this->hash;
	}
}

