<?php
/**
 * Salt
 *
 * A collections of [NaCl](http://nacl.cr.yp.to/) cryptography library for PHP.
 *
 * 
 * @link   https://github.com/devi/Salt
 *
 */
class Salt {

	/* Salsa20, HSalsa20, XSalsa20 */
	const salsa20_KEY    = 32;
	const salsa20_NONCE  =  8;
	const salsa20_INPUT  = 16;
	const salsa20_OUTPUT = 64;
	const salsa20_CONST  = 16;

	const hsalsa20_KEY    = 32;
	const hsalsa20_INPUT  = 16;
	const hsalsa20_OUTPUT = 32;
	const hsalsa20_CONST  = 16;

	const xsalsa20_KEY   = 32;
	const xsalsa20_NONCE = 24;

	/* Stream salsa20, salsa20_xor */
	const stream_salsa20_KEY   = 32;
	const stream_salsa20_NONCE = 24;

	/* Poly1305 */
	const poly1305_KEY    = 32;
	const poly1305_OUTPUT = 16;

	/* Onetimeauth */
	const onetimeauth_KEY    = 32;
	const onetimeauth_OUTPUT = 16;

	/* Secretbox */
	const secretbox_KEY     = 32;
	const secretbox_NONCE   = 24;
	const secretbox_ZERO    = 32;
	const secretbox_BOXZERO = 16;

	/* Scalarmult */
	const scalarmult_INPUT  = 32;
	const scalarmult_SCALAR = 32;

	/* Box */
	const box_PRIVATEKEY = 32;
	const box_PUBLICKEY  = 32;
	const box_NONCE      = 24;

	/* Sign */
	const sign_PRIVATEKEY = 64;
	const sign_PUBLICKEY  = 32;
	const sign_SIGNATURE  = 64;

	protected static $instance;

	public static function instance() {
		if (!isset(static::$instance)) {
			static::$instance = new Salt();
		}
		return static::$instance;
	}

	/**
	 * Helper function to generate random string.
	 *
	 * @param  int
	 * @return string
	 */
	public static function randombytes($length = 32) {
		$raw = '';
		if (is_readable('/dev/urandom')) {
			$fp = true;
			if ($fp === true) {
				$fp = @fopen('/dev/urandom', 'rb');
			}
			if ($fp !== true && $fp !== false) {
				$raw = fread($fp, $length);
			}
		} else if (function_exists('mcrypt_create_iv')) {
			$raw = mcrypt_create_iv($length, MCRYPT_DEV_URANDOM);
		} else if (function_exists('openssl_random_pseudo_bytes')) {
			$raw = openssl_random_pseudo_bytes($length);
		}
		if (!$raw || strlen($raw) !== $length) {
			throw new SaltException('Unable to generate randombytes');
		}
		return $raw;
	}

	/**
	 * Returns true if $x === $y
	 *
	 * @param array
	 * @param array
	 * @return bool
	 */
	public static function equal($x, $y) {
		$len = count($x);
		if ($len !== count($y)) return false;

		$diff = 0;
		for ($i = 0; $i < $len; $i++) {
			$diff |= $x[$i] ^ $y[$i];
		}
		$diff = ($diff - 1) >> 31;

		return (($diff & 1) === 1);
	}

	public function crypto_core_salsa20($in, $key, $const) {
		$out = new FieldElement(32);
		Salsa20::instance()->core($out, $in, $key, $const);
		return $out;
	}

	public function crypto_core_hsalsa20($in, $key, $const) {
		$out = new FieldElement(32);
		Salsa20::instance()->core($out, $in, $key, $const, false);
		return $out;
	}

	public function crypto_onetimeauth($in, $length, $key) {
		$mac = new FieldElement(16);
		Poly1305::auth($mac, $in, $length, $key);
		return $mac;
	}

	public function crypto_onetimeauth_verify($mac, $in, $length, $key) {
		$correct = $this->crypto_onetimeauth($in, $length, $key);
		return Salt::equal($correct, $mac->slice(0, 16));
	}

	public function crypto_stream_salsa20($length, $nonce, $key) {
		$out = new FieldElement($length);
		Salsa20::instance()->stream($out, false, $length, $nonce, $key);
		return $out;
	}

	public function crypto_stream_salsa20_xor($in, $length, $nonce, $key) {
		$out = new FieldElement($length);
		Salsa20::instance()->stream($out, $in, $length, $nonce, $key);
		return $out;
	}

	public function crypto_stream_xsalsa20($length, $nonce, $key) {
		$subkey = $this->crypto_core_hsalsa20($nonce, $key, Salsa20::$sigma);
		return $this->crypto_stream_salsa20($length, $nonce->slice(16), $subkey);
	}

	public function crypto_stream_xsalsa20_xor($in, $length, $nonce, $key) {
		$subkey = $this->crypto_core_hsalsa20($nonce, $key, Salsa20::$sigma);
		return $this->crypto_stream_salsa20_xor($in, $length, $nonce->slice(16), $subkey);
	}

	public function crypto_stream($length, $nonce, $key) {
		return $this->crypo_stream_xsalsa20($length, $nonce, $key);
	}

	public function crypto_stream_xor($in, $length, $nonce, $key) {
		return $this->crypo_stream_xsalsa20_xor($in, $length, $nonce, $key);
	}

	public function crypto_secretbox($message, $length, $nonce, $key) {
		if ($length < 32) return false;
		$out = $this->crypto_stream_xsalsa20_xor($message, $length, $nonce, $key);
		$mac = $this->crypto_onetimeauth($out->slice(32), $length-32, $out);
		for ($i = 0; $i < 16;++$i) {
			$out[$i] = 0;
			$out[$i+16] = $mac[$i];
		}
		return $out;
	}

	public function crypto_secretbox_open($ciphertext, $length, $nonce, $key) {
		if ($length < 32) return false;
		$subkey = $this->crypto_stream_xsalsa20(32, $nonce, $key);
		if (!$this->crypto_onetimeauth_verify(
				$ciphertext->slice(16),
				$ciphertext->slice(32),
				$length - 32,
				$subkey
			)) return false;
		$out = $this->crypto_stream_xsalsa20_xor($ciphertext, $length, $nonce, $key);
		for ($i = 0;$i < 32;++$i) $out[$i] = 0;
		return $out;
	}

	public function crypto_scalarmult($in, $scalar) {
		return FieldElement::fromArray(
			Curve25519::instance()->scalarmult($in, $scalar)->toArray()
		);
	}

	public function crypto_scalarmult_base($in) {
		return FieldElement::fromArray(
			Curve25519::instance()->scalarbase($in)->toArray()
		);
	}

	public function crypto_box_keypair() {
		$sk = FieldElement::fromString(Salt::randombytes());
		$pk = $this->crypto_scalarmult_base($sk);
		return array($sk, $pk);
	}

	public function crypto_box_beforenm($publickey, $privatekey) {
		$s = $this->crypto_scalarmult($privatekey, $publickey);
		return $this->crypto_core_hsalsa20(new FieldElement(16), $s, Salsa20::$sigma);
	}

	public function crypto_box_afternm($input, $length, $nonce, $key) {
		return $this->crypto_secretbox($input, $length, $nonce, $key);
	}

	public function crypto_box($input, $length, $nonce, $publickey, $privatekey) {
		$subkey = $this->crypto_box_beforenm($publickey, $privatekey);
		$inlen = count($input);
		$in = new FieldElement($inlen+32);
		for ($i = 32; $i--;) $in[$i] = 0; // pad 32 byte
		for ($i = 0;$i < $inlen;++$i) $in[$i+32] = $input[$i];
		return $this->crypto_box_afternm($in, $length+32, $nonce, $subkey);
	}

	public function crypto_box_open_afternm($ciphertext, $length, $nonce, $key) {
		return $this->crypto_secretbox_open($ciphertext, $length, $nonce, $key);
	}

	public function crypto_box_open($ciphertext, $length, $nonce, $publickey, $privatekey) {
		$subkey = $this->crypto_box_beforenm($publickey, $privatekey);
		return $this->crypto_box_open_afternm($ciphertext, $length, $nonce, $subkey);
	}

	/**
	 * Generates a secret key and a corresponding public key.
	 *
	 * @param  mixed   32 byte random string
	 * @return array   private key, public key
	 */
	public function crypto_sign_keypair($seed = null) {
		if ($seed === null) {
			$sk = FieldElement::fromString(Salt::randombytes());
		} else {
			$sk = Salt::decodeInput($seed);
			if ($sk->count() !== Salt::sign_PUBLICKEY) {
				throw new SaltException('crypto_sign_keypair: seed must be 32 byte');
			}
		}

		$az = self::hash($sk->toString());
		$az[0] &= 248;
		$az[31] &= 63;
		$az[31] |= 64;

		$ed = Ed25519::instance();
		$A = new GeExtended();
		$pk = new FieldElement(32);
		$ed->geScalarmultBase($A, $az);
		$ed->GeExtendedtoBytes($pk, $A);

		$sk->setSize(64);
		$sk->copy($pk, 32, 32);

		return array($sk, $pk);
	}
	
	public function crypto_sign_public_from_secret_key($sk) {
		$sk = Salt::decodeInput($sk);
		if($sk->count() == 64) {
			// its the extended sk, get just the last 32 bytes
			$sk->slice(32, 32);
		} else if($sk->count() != 32) {
			throw new SaltException('crypto_sign_public_from_secret_key: secret key should be 32 or 64 bytes long');
		}
		
		$az = self::hash($sk->toString());
		$az[0] &= 248;
		$az[31] &= 63;
		$az[31] |= 64;

		$ed = Ed25519::instance();
		$A = new GeExtended();
		$pk = new FieldElement(32);
		$ed->geScalarmultBase($A, $az);
		$ed->GeExtendedtoBytes($pk, $A);

		return $pk;
	}

	/**
	 * Signs a message using the signer's private key and returns
	 * the signed message.
	 *
	 * @param  mixed   message to be signed
	 * @param  int     message length to be signed
	 * @param  mixed   private key
	 * @return FieldElement  signed message
	 */
	public function crypto_sign($msg, $mlen, $secretkey) {
		$sk = Salt::decodeInput($secretkey);

		if ($sk->count() !== Salt::sign_PRIVATEKEY) {
			throw new SaltException('crypto_sign: private key must be 64 byte');
		}

		$pk = $sk->slice(32, 32);

		$az = self::hash($sk->slice(0,32)->toString());
		$az[0] &= 248;
		$az[31] &= 63;
		$az[31] |= 64;

		$m = Salt::decodeInput($msg);

		$sm = new FieldElement($mlen + 64);
		$sm->copy($m, $mlen, 64);
		$sm->copy($az, 32, 32, 32);

		$nonce = self::hash($sm->slice(32,$mlen+32)->toString());
		
		$sm->copy($pk, 32, 32);

		$ed = Ed25519::instance();
		$R = new GeExtended();
		$ed->scReduce($nonce);
		$ed->geScalarmultBase($R, $nonce);
		$ed->GeExtendedtoBytes($sm, $R);

		$hram = self::hash($sm->toString());
		$ed->scReduce($hram);

		$rest = new FieldElement(32);
		$ed->scMulAdd($rest, $hram, $az, $nonce);
		$sm->copy($rest, 32, 32);

		return $sm;
	}

	/**
	 * Verifies the signature of a signed message using signer's publickey.
	 *
	 * @param  mixed  signed message
	 * @param  int    signed message length
	 * @param  mixed  signer's public key
	 * @return mixed
	 */
	public function crypto_sign_open($signedmsg, $smlen, $publickey) {
		$sm = Salt::decodeInput($signedmsg);
		$pk = Salt::decodeInput($publickey);

		if ($smlen < 64) return false;

		if ($sm[63] & 224) return false;

		$ed = Ed25519::instance();
		$A  = new GeExtended();

		if (!$ed->geFromBytesNegateVartime($A, $pk)) {
			return false;
		}

		$d = 0;
		for ($i = 0;$i < 32;++$i) $d |= $pk[$i];
		if ($d === 0) return false;
		
		$b2b = new Blake2b();
		$ctx = $b2b->init();
		$b2b->update($ctx, $sm->slice(0, 32), 32);
		$b2b->update($ctx, $pk, 32);
		$b2b->update($ctx, $sm->slice(64, $smlen - 64), $sm->slice(64, $smlen - 64)->count());
		$h = new FieldElement(64);
		$b2b->finish($ctx, $h);
		$ed->scReduce($h);

		$R = new GeProjective();
		$rcheck = new FieldElement(32);
		$ed->geDoubleScalarmultVartime($R, $h, $A, $sm->slice(32));
		$ed->geToBytes($rcheck, $R);

		if ($ed->cryptoVerify32($rcheck, $sm) === 0) {
			return $sm->slice(64, $smlen-64);
		}

		return false;
	}
	
	public function crypto_sign_open2($msg, $sm, $n, $pk) {
		$sm = Salt::decodeInput($sm);
		
		if($n < 64) return false;
		
		$m = [];
		for($i = 0; $i < count($msg); $i++) $m[$i] = $msg[$i];
		
		$ed = Ed25519::instance();
		$A  = new GeExtended();

		if (!$ed->geFromBytesNegateVartime($A, $pk)) {
			return false;
		}
		
		for ($i = 0; $i < $n; $i++) $m[$i] = $sm[$i];
		for ($i = 0; $i < 32; $i++) $m[$i+32] = $pk[$i];
		
		$h = self::hash($m);
		
		$ed->scReduce($h);
		
		$R = new GeProjective();
		$rcheck = new FieldElement(32);
		$ed->geDoubleScalarmultVartime($R, $h, $A, $sm->slice(32));
		$ed->geToBytes($rcheck, $R);
		
		if ($ed->cryptoVerify32($rcheck, $sm) === 0) {
			return $sm->slice(64, $n-64);
		}
	}

	/**
	 * Get bytes presentation from a value.
	 *
	 * @param  mixed
	 * @return FieldElement
	 */
	public static function decodeInput($value) {
		if (is_string($value)) {
			return FieldElement::fromString($value);
		} else if ($value instanceof FieldElement) {
			return $value;
		} else if ($value instanceof SplFixedArray) {
			return FieldElement::fromArray($value->toArray(), false);
		} else if ((array) $value === $value) {
			return FieldElement::fromArray($value, false);
		}
		throw new SaltException('Unexpected input');
	}

	/* High level API */

	/**
	 * Authenticates a message using a secret key.
	 * 
	 * @param  mixed  message to be authenticated
	 * @param  mixed  32 bytes secret key
	 * @return FieldElement  16 bytes authenticator
	 */
	public static function onetimeauth($msg, $key) {
		$k = Salt::decodeInput($key);
		if ($k->count() !== Salt::onetimeauth_KEY) {
			throw new SaltException('Invalid key size');
		}
		$in = Salt::decodeInput($msg);
		return Salt::instance()->crypto_onetimeauth($in, $in->count(), $k);
	}

	/**
	 * Check if $mac is a correct authenticator of a message under a secret key.
	 *
	 * @return bool
	 */
	public static function onetimeauth_verify($mac, $msg, $secretkey) {
		$t = Salt::decodeInput($mac);
		$m = Salt::decodeInput($msg);
		$k = Salt::decodeInput($secretkey);
		if ($t->count() !== Salt::onetimeauth_OUTPUT) {
			throw new SaltException('Invalid mac size');
		}
		if ($k->count() !== Salt::onetimeauth_KEY) {
			throw new SaltException('Invalid secret key size');
		}
		return Salt::instance()->crypto_onetimeauth_verify($t, $m, $m->count(), $k);
	}

	/**
	 * Encrypts and authenticates a message using a secret key and a nonce.
	 *
	 * @param  mixed  message to be encrypted and authenticated
	 * @param  mixed  24 bytes nonce
	 * @param  mixed  32 bytes secret key
	 * @return FieldElement
	 */
	public static function secretbox($msg, $nonce, $key) {
		$k = Salt::decodeInput($key);
		$n = Salt::decodeInput($nonce);

		if ($k->count() !== Salt::secretbox_KEY) {
			throw new SaltException('Invalid key size');
		}
		if ($n->count() !== Salt::secretbox_NONCE) {
			throw new SaltException('Invalid nonce size');
		}

		$in = new FieldElement(32);
		for ($i = 32; $i--;) $in[$i] = 0; // zero padding 32 byte

		$data = Salt::decodeInput($msg);

		$in->setSize(32 + $data->count());

		$in->copy($data, $data->count(), 32);

		return Salt::instance()->crypto_secretbox($in, $in->count(), $n, $k);
	}

	/**
	 * Verifies and decrypts a chipertext using a secret key and a nonce.
	 *
	 * @param  mixed  chipertext to be verified and decrypted
	 * @param  mixed  24 bytes nonce
	 * @param  mixed  32 bytes secret key
	 * @return FieldElement
	 */
	public static function secretbox_open($ciphertext, $nonce, $key) {
		$k = Salt::decodeInput($key);
		$n = Salt::decodeInput($nonce);

		if ($k->count() !== Salt::secretbox_KEY) {
			throw new SaltException('Invalid key size');
		}
		if ($n->count() !== Salt::secretbox_NONCE) {
			throw new SaltException('Invalid nonce size');
		}

		$in = Salt::decodeInput($ciphertext);

		return Salt::instance()->crypto_secretbox_open($in, $in->count(), $n, $k);
	}

	/**
	 * Curve25519 scalar multiplication.
	 * 
	 * @param  mixed  32 byte secret key
	 * @param  mixed  32 byte public key
	 * @return FieldElement
	 */
	public static function scalarmult($secretkey, $publickey) {
		$sk = Salt::decodeInput($secretkey);
		$pk = Salt::decodeInput($publickey);
		if ($sk->count() !== Salt::scalarmult_INPUT) {
			throw new SaltException('Invalid secret key size');
		}
		if ($pk->count() !== Salt::scalarmult_SCALAR) {
			throw new SaltException('Invalid public key size');
		}
		return Salt::instance()->crypto_scalarmult($sk, $pk);
	}

	/**
	 * Curve25519 scalar base multiplication.
	 * 
	 * @param  mixed  32 byte secret key
	 * @return FieldElement
	 */
	public static function scalarmult_base($secretkey) {
		$sk = Salt::decodeInput($secretkey);
		if ($sk->count() !== Salt::scalarmult_INPUT) {
			throw new SaltException('Invalid secret key size');
		}
		return Salt::instance()->crypto_scalarmult_base($sk);
	}

	/**
	 * Encrypts and authenticates a message using sender's secret key,
	 * receiver's public key and a nonce.
	 *
	 * @param  mixed  the message
	 * @param  mixed  32 byte sender's secret key
	 * @param  mixed  32 byte receiver's public key
	 * @param  mixed  24 byte nonce
	 * @return FieldElement chipertext
	 */
	public static function box($msg, $secretkey, $publickey, $nonce) {
		$in = Salt::decodeInput($msg);
		$sk = Salt::decodeInput($secretkey);
		$pk = Salt::decodeInput($publickey);
		$n = Salt::decodeInput($nonce);
		if ($sk->count() !== Salt::box_PRIVATEKEY) {
			throw new SaltException('Invalid secret key size');
		}
		if ($pk->count() !== Salt::box_PUBLICKEY) {
			throw new SaltException('Invalid public key size');
		}
		if ($n->count() !== Salt::box_NONCE) {
			throw new SaltException('Invalid nonce size');
		}
		return Salt::instance()->crypto_box($in, $in->count(), $n, $pk, $sk);
	}

	/**
	 * Decrypts a chipertext using the receiver's secret key,
	 * sender's public key and a nonce.
	 *
	 * @param  mixed  chipertext
	 * @param  mixed  32 byte receiver's secret key
	 * @param  mixed  32 byte sender's public key
	 * @param  mixed  24 byte nonce
	 * @return FieldElement the message
	 */
	public static function box_open($ciphertext, $secretkey, $publickey, $nonce) {
		$c = Salt::decodeInput($ciphertext);
		$sk = Salt::decodeInput($secretkey);
		$pk = Salt::decodeInput($publickey);
		$n = Salt::decodeInput($nonce);
		if ($sk->count() !== Salt::box_PRIVATEKEY) {
			throw new SaltException('Invalid secret key size');
		}
		if ($pk->count() !== Salt::box_PUBLICKEY) {
			throw new SaltException('Invalid public key size');
		}
		if ($n->count() !== Salt::box_NONCE) {
			throw new SaltException('Invalid nonce size');
		}
		return Salt::instance()->crypto_box_open($c, $c->count(), $n, $pk, $sk);
	}

	/**
	 * Generates a secret key and a corresponding public key.
	 *
	 * @return array  secret key, public key
	 */
	public static function box_keypair() {
		return Salt::instance()->crypto_box_keypair();
	}

	/**
	 * Signs a message using the signer's private key and returns the signature.
	 *
	 * @param  mixed   message to be signed
	 * @param  mixed   sender's secret key
	 * @return FieldElement 64 byte signature 
	 */
	public static function sign($msg, $secretkey) {
		$m = Salt::decodeInput($msg);
		$sm = Salt::instance()->crypto_sign($m, $m->count(), $secretkey);
		return $sm->slice(0, 64);
	}

	/**
	 * Verifies the signature of a message using signer's publickey.
	 *
	 * @param  mixed  the message
	 * @param  mixed  signature
	 * @param  mixed  signer's public key
	 * @param  string optional hash algorithm
	 * @return bool
	 */
	public static function sign_verify($msg, $signature, $publickey) {
		$sm = Salt::decodeInput($signature);
		$m = Salt::decodeInput($msg);
		$sm->setSize($sm->count() + $m->count());
		$sm->copy($m, $m->count, 64);
		$pk = Salt::decodeInput($publickey);
		$ret = Salt::instance()->crypto_sign_open($sm, $sm->count(), $pk);
		return ($ret !== false);
	}

	/**
	 * Generates a secret key and a corresponding public key.
	 *
	 * @param  mixed   optional random 32 byte
	 * @return array   secret key, public key
	 */
	public static function sign_keypair($seed = null) {
		return Salt::instance()->crypto_sign_keypair($seed);
	}

	/**
	 * Chacha20Poly1305 AEAD encryption.
	 *
	 * @param  mixed  message to be encrypted
	 * @param  mixed  associated data
	 * @param  mixed  8 byte nonce
	 * @param  mixed  32 byte secret key
	 * @return FieldElement ciphertext
	 */
	public static function encrypt($input, $data, $nonce, $secretkey) {
		$in = Salt::decodeInput($input);
		$ad = Salt::decodeInput($data);
		$n = Salt::decodeInput($nonce);
		$k = Salt::decodeInput($secretkey);
		if ($k->count() !== Chacha20::KeySize) {
			throw new SaltException('Invalid key size');
		}
		if ($n->count() !== Chacha20::NonceSize) {
			throw new SaltException('Invalid nonce size');
		}

		$aead = new Chacha20Poly1305($k);
		return $aead->encrypt($n, $in, $ad);
	}

	/**
	 * Chacha20Poly1305 AEAD decryption.
	 *
	 * @param  mixed  ciphertext to be decrypted
	 * @param  mixed  associated data
	 * @param  mixed  8 byte nonce
	 * @param  mixed  32 byte secret key
	 * @return FieldElement the message
	 */
	public static function decrypt($ciphertext, $data, $nonce, $secretkey) {
		$in = Salt::decodeInput($ciphertext);
		$ad = Salt::decodeInput($data);
		$n = Salt::decodeInput($nonce);
		$k = Salt::decodeInput($secretkey);
		if ($k->count() !== Chacha20::KeySize) {
			throw new SaltException('Invalid key size');
		}
		if ($n->count() !== Chacha20::NonceSize) {
			throw new SaltException('Invalid nonce size');
		}

		$aead = new Chacha20Poly1305($k);
		return $aead->decrypt($n, $in, $ad);
	}

	/**
	 * Generate hash value using Blake2b.
	 *
	 * @param  mixed  data to be hashed
	 * @param  mixed  optional secret key (64 byte max)
	 * @return FieldElement 64 byte
	 */
	public static function hash($str, $key = null) {
		$b2b = new Blake2b();

		$k = $key;
		if ($key !== null) {
			$k = Salt::decodeInput($key);
			if ($k->count() > $b2b::KEYBYTES) {
				throw new SaltException('Invalid key size');
			}
		}

		$in = Salt::decodeInput($str);

		$ctx = $b2b->init($k);
		$b2b->update($ctx, $in, $in->count());

		$out = new FieldElement(Blake2b::OUTBYTES);
		$b2b->finish($ctx, $out);

		return $out;
	}


}
