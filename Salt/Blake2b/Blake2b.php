<?php
/**
 * Blake2b - Doesn't support tree hashing (yet).
 *
 *
 * Ported by Devi Mandiri. Public Domain.
 * 
 * @link https://github.com/devi/Salt
 */
class Blake2b {

	const BLOCKBYTES = 128;
	const OUTBYTES   = 64;
	const KEYBYTES   = 64;

	protected function new64($high, $low) {
		$i64 = new SplFixedArray(2);
		$i64[0] = $high & 0xffffffff;
		$i64[1] = $low & 0xffffffff;
		return $i64;
	}

	protected function to64($num) {
		$hi = 0; $lo = $num & 0xffffffff;

		if ((+(abs($num))) >= 1) {
			if ($num > 0) {
				$hi = min((+(floor($num/4294967296))), 4294967295);
			} else {
				$hi = ~~((+(ceil(($num - (+((~~($num)))))/4294967296))));
			}
		}

		return $this->new64($hi, $lo);
	}

	protected function add64($x, $y) {
		$l = ($x[1] + $y[1]) & 0xffffffff;
		return $this->new64($x[0] + $y[0] + (($l < $x[1]) ? 1 : 0), $l);
	}

	protected function add364($x, $y, $z) {
		return $this->add64($x, $this->add64($y, $z));
	}

	protected function xor64($x, $y) {
		return $this->new64($x[0] ^ $y[0], $x[1] ^ $y[1]);
	}

	protected function rotr64($x, $c) {
		$h0 = 0;
		$l0 = 0;
		$c = 64 - $c;

		if ($c < 32) {
			$h0 = ($x[0] << $c) | (($x[1] & ((1 << $c) - 1) << (32 - $c)) >> (32 - $c));
			$l0 = $x[1] << $c;
		} else {
			$h0 = $x[1] << ($c - 32);
		}

		$h1 = 0;
		$l1 = 0;
		$c1 = 64 - $c;

		if ($c1 < 32) {
			$h1 = $x[0] >> $c1;
			$l1 = ($x[1] >> $c1) | ($x[0] & ((1 << $c1) - 1)) << (32 - $c1);
		} else {
			$l1 = $x[0] >> ($c1 - 32);
		}

		return $this->new64($h0 | $h1, $l0 | $l1);
	}

	protected function flatten64($x) {
		return ($x[0] * 4294967296 + $x[1]);
	}

	protected function load64($x, $i) {
		$l = $x[$i]   | ($x[$i+1]<<8) | ($x[$i+2]<<16) | ($x[$i+3]<<24);
		$h = $x[$i+4] | ($x[$i+5]<<8) | ($x[$i+6]<<16) | ($x[$i+7]<<24);
		return $this->new64($h, $l);
	}

	protected function store64($x, $i, $u) {
		$x[$i]   = ($u[1] & 0xff); $u[1] >>= 8;
		$x[$i+1] = ($u[1] & 0xff); $u[1] >>= 8;
		$x[$i+2] = ($u[1] & 0xff); $u[1] >>= 8;
		$x[$i+3] = ($u[1] & 0xff);
		$x[$i+4] = ($u[0] & 0xff); $u[0] >>= 8;
		$x[$i+5] = ($u[0] & 0xff); $u[0] >>= 8;
		$x[$i+6] = ($u[0] & 0xff); $u[0] >>= 8;
		$x[$i+7] = ($u[0] & 0xff);
	}

	protected $iv;

	protected $sigma = array(
		array(  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15),
		array( 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3),
		array( 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4),
		array(  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8),
		array(  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13),
		array(  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9),
		array( 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11),
		array( 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10),
		array(  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5),
		array( 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13 , 0),
		array(  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15),
		array( 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3)
	);

	public function __construct() {
		$this->iv = new SplFixedArray(8);
		$this->iv[0] = $this->new64(0x6a09e667, 0xf3bcc908);
		$this->iv[1] = $this->new64(0xbb67ae85, 0x84caa73b);
		$this->iv[2] = $this->new64(0x3c6ef372, 0xfe94f82b);
		$this->iv[3] = $this->new64(0xa54ff53a, 0x5f1d36f1);
		$this->iv[4] = $this->new64(0x510e527f, 0xade682d1);
		$this->iv[5] = $this->new64(0x9b05688c, 0x2b3e6c1f);
		$this->iv[6] = $this->new64(0x1f83d9ab, 0xfb41bd6b);
		$this->iv[7] = $this->new64(0x5be0cd19, 0x137e2179);
	}

	protected function context() {
		$ctx    = new SplFixedArray(5);
		$ctx[0] = new SplFixedArray(8);   // h
		$ctx[1] = new SplFixedArray(2);   // t 
		$ctx[2] = new SplFixedArray(2);   // f
		$ctx[3] = new SplFixedArray(256); // buf
		$ctx[4] = 0;                      // buflen

		for ($i = 8; $i--;) {
			$ctx[0][$i] = $this->iv[$i];
		}
		for ($i = 256; $i--;) {
			$ctx[3][$i] = 0;
		}

		$zero = $this->new64(0, 0);
		$ctx[1][0] = $zero;
		$ctx[1][1] = $zero;
		$ctx[2][0] = $zero;
		$ctx[2][1] = $zero;

		return $ctx;
	}

	protected function compress($ctx, $buf) {
		$m = new SplFixedArray(16);
		$v = new SplFixedArray(16);

		for ($i = 16; $i--;) {
			$m[$i] = $this->load64($buf, $i*8);
		}

		for ($i = 8; $i--;) {
			$v[$i] = $ctx[0][$i];
		}

		$v[ 8] = $this->iv[0];
		$v[ 9] = $this->iv[1];
		$v[10] = $this->iv[2];
		$v[11] = $this->iv[3];

		$v[12] = $this->xor64($ctx[1][0], $this->iv[4]);
		$v[13] = $this->xor64($ctx[1][1], $this->iv[5]);
		$v[14] = $this->xor64($ctx[2][0], $this->iv[6]);
		$v[15] = $this->xor64($ctx[2][1], $this->iv[7]);

		$G = function ($r, $i, $a, $b, $c, $d) use ($v, $m) {
			$v[$a] = $this->add364($v[$a], $v[$b], $m[$this->sigma[$r][2*$i]]);
			$v[$d] = $this->rotr64($this->xor64($v[$d], $v[$a]), 32);
			$v[$c] = $this->add64($v[$c], $v[$d]);
			$v[$b] = $this->rotr64($this->xor64($v[$b], $v[$c]), 24);
			$v[$a] = $this->add364($v[$a], $v[$b], $m[$this->sigma[$r][2*$i+1]]);
			$v[$d] = $this->rotr64($this->xor64($v[$d], $v[$a]), 16);
			$v[$c] = $this->add64($v[$c], $v[$d]);
			$v[$b] = $this->rotr64($this->xor64($v[$b], $v[$c]), 63);
		};

		for ($r = 0; $r < 12; ++$r) {
			$G($r, 0,  0,  4,  8, 12);
			$G($r, 1,  1,  5,  9, 13);
			$G($r, 2,  2,  6, 10, 14);
			$G($r, 3,  3,  7, 11, 15);
			$G($r, 4,  0,  5, 10, 15);
			$G($r, 5,  1,  6, 11, 12);
			$G($r, 6,  2,  7,  8, 13);
			$G($r, 7,  3,  4,  9, 14);
		}

		for ($i = 8; $i--;) {
			$ctx[0][$i] = $this->xor64(
				$ctx[0][$i], $this->xor64($v[$i], $v[$i+8])
			);
		}
	}

	protected function increment_counter($ctx, $inc) {
		$t = $this->to64($inc);
		$ctx[1][0] = $this->add64($ctx[1][0], $t);
		if ($this->flatten64($ctx[1][0]) < $inc) {
			$ctx[1][1] = $this->add64($ctx[1][1], $this->to64(1));
		}
	}

	public function update($ctx, $p, $plen) {
		$offset = 0; $left = 0; $fill = 0;
		while ($plen > 0) {
			$left = $ctx[4];
			$fill = 256 - $left;

			if ($plen > $fill) {
				for ($i = $fill; $i--;) {
					$ctx[3][$i+$left] = $p[$i+$offset];
				}

				$ctx[4] += $fill;

				$this->increment_counter($ctx, 128);
				$this->compress($ctx, $ctx[3]);

				for ($i = 128; $i--;) {
					$ctx[3][$i] = $ctx[3][$i+128];
				}

				$ctx[4] -= 128;
				$offset += $fill;
				$plen -= $fill;
			} else {
				for ($i = $plen; $i--;) {
					$ctx[3][$i+$left] = $p[$i+$offset];
				}
				$ctx[4] += $plen;
				$offset += $plen;
				$plen -= $plen;
			}
		}
	}

	public function finish($ctx, $out) {
		if ($ctx[4] > 128) {
			$this->increment_counter($ctx, 128);
			$this->compress($ctx, $ctx[3]);
			$ctx[4] -= 128;
			for ($i = $ctx[4]; $i--;) {
				$ctx[3][$i] = $ctx[3][$i+128];
			}
		}

		$this->increment_counter($ctx, $ctx[4]);
		$ctx[2][0] = $this->new64(0xffffffff, 0xffffffff);

		for ($i = 256 - $ctx[4]; $i--;) {
			$ctx[3][$i+$ctx[4]] = 0;
		}

		$this->compress($ctx, $ctx[3]);

		for ($i = 8; $i--;) {
			$this->store64($out, $i*8, $ctx[0][$i]);
		}
	}

	public function init($key = null, $outlen = 64) {
		$klen = 0;

		if ($key !== null) {
			if (count($key) > 64) return false;
			$klen = count($key);
		}

		if ($outlen > 64) return false;

		$ctx = $this->context();

		$p = new SplFixedArray(64);
		for ($i = 64; $i--;) $p[$i] = 0;

		$p[0] = $outlen; // digest_length
		$p[1] = $klen;   // key_length
		$p[2] = 1;       // fanout
		$p[3] = 1;       // depth

		$ctx[0][0] = $this->xor64($ctx[0][0], $this->load64($p, 0));

		if ($klen > 0) {
			$block = new SplFixedArray(128);
			for ($i = 128; $i--;) $block[$i] = 0;
			for ($i = $klen; $i--;) $block[$i] = $key[$i];
			$this->update($ctx, $block, 128);
		}

		return $ctx;
	}

}
