<?php
/**
 * Poly1305
 *
 * Implementation derived from poly1305-donna-16.h
 * See for details: https://github.com/floodyberry/poly1305-donna
 *
 * @link   https://github.com/devi/Salt
 */
class Poly1305 {

	const KeySize = 32;

	const TagSize = 16;

	protected function U8TO16($p, $pos) {
		return (($p[$pos] & 0xff) & 0xffff) | ((($p[$pos+1] & 0xff) & 0xffff) << 8);
	}

	protected function U16TO8($p, $pos, $v) {
		$p[$pos]   = ($v     ) & 0xff;
		$p[$pos+1] = ($v >> 8) & 0xff;
	}

	public function init($key) {
		$ctx    = new SplFixedArray(6);
		$ctx[0] = new SplFixedArray(16); // buffer
		$ctx[1] = 0;                     // leftover
		$ctx[2] = new SplFixedArray(10); // r
		$ctx[3] = new SplFixedArray(10); // h
		$ctx[4] = new SplFixedArray(8);  // pad
		$ctx[5] = 0;                     // final

		$t = new SplFixedArray(8);

		for ($i = 8; $i--;) $t[$i] = $this->U8TO16($key, $i*2);

		$ctx[2][0] =   $t[0]                         & 0x1fff;
		$ctx[2][1] = (($t[0] >> 13) | ($t[1] <<  3)) & 0x1fff;
		$ctx[2][2] = (($t[1] >> 10) | ($t[2] <<  6)) & 0x1f03;
		$ctx[2][3] = (($t[2] >>  7) | ($t[3] <<  9)) & 0x1fff;
		$ctx[2][4] = (($t[3] >>  4) | ($t[4] << 12)) & 0x00ff;
		$ctx[2][5] =  ($t[4] >>  1)                  & 0x1ffe;
		$ctx[2][6] = (($t[4] >> 14) | ($t[5] <<  2)) & 0x1fff;
		$ctx[2][7] = (($t[5] >> 11) | ($t[6] <<  5)) & 0x1f81;
		$ctx[2][8] = (($t[6] >>  8) | ($t[7] <<  8)) & 0x1fff;
		$ctx[2][9] =  ($t[7] >>  5)                  & 0x007f;

		for ($i = 8; $i--;) {
			$ctx[3][$i] = 0;
			$ctx[4][$i] = $this->U8TO16($key, 16+(2*$i));
		}

		$ctx[3][8] = 0;
		$ctx[3][9] = 0;
		$ctx[1] = 0;
		$ctx[5] = 0;

		return $ctx;  
	}
 
	protected function blocks($ctx, $m, $mpos, $bytes) {
		$hibit = $ctx[5] ? 0 : (1 << 11);
		$t = new SplFixedArray(8);
		$d = new SplFixedArray(10);
		$c = 0;

		while ($bytes >= 16) {
			for ($i = 8; $i--;) $t[$i] = $this->U8TO16($m, $i*2+$mpos);

			$ctx[3][0] +=   $t[0]                         & 0x1fff;
			$ctx[3][1] += (($t[0] >> 13) | ($t[1] <<  3)) & 0x1fff;
			$ctx[3][2] += (($t[1] >> 10) | ($t[2] <<  6)) & 0x1fff;
			$ctx[3][3] += (($t[2] >>  7) | ($t[3] <<  9)) & 0x1fff;
			$ctx[3][4] += (($t[3] >>  4) | ($t[4] << 12)) & 0x1fff;
			$ctx[3][5] +=  ($t[4] >>  1)                  & 0x1fff;
			$ctx[3][6] += (($t[4] >> 14) | ($t[5] <<  2)) & 0x1fff;
			$ctx[3][7] += (($t[5] >> 11) | ($t[6] <<  5)) & 0x1fff;
			$ctx[3][8] += (($t[6] >>  8) | ($t[7] <<  8)) & 0x1fff;
			$ctx[3][9] +=  ($t[7] >>  5) | $hibit;
 
			for ($i = 0, $c = 0; $i < 10; $i++) {
				$d[$i] = $c;
				for ($j = 0; $j < 10; $j++) {
					$d[$i] += ($ctx[3][$j] & 0xffffffff) * (($j <= $i) ? $ctx[2][$i-$j] : (5 * $ctx[2][$i+10-$j]));
					if ($j === 4) {
						$c = ($d[$i] >> 13);
						$d[$i] &= 0x1fff;
					}
				}
				$c += ($d[$i] >> 13);
				$d[$i] &= 0x1fff;
			}
			$c = (($c << 2) + $c);
			$c += $d[0];
			$d[0] = (($c & 0xffff) & 0x1fff);
			$c = ($c >> 13);
			$d[1] += $c;

			for ($i = 10; $i--;) $ctx[3][$i] = $d[$i] & 0xffff;

			$mpos  += 16;
			$bytes -= 16;
		}
	}

	public function update($ctx, $m, $bytes) {
		$want = 0; $mpos = 0;

		if ($ctx[1]) {
			$want = 16 - $ctx[1];
			if ($want > $bytes) $want = $bytes;
			for ($i = $want; $i--;) {
				$ctx[0][$ctx[1]+$i] = $m[$i+$mpos];
			}
			$bytes  -= $want;
			$mpos   += $want;
			$ctx[1] += $want;
			if ($ctx[1] < 16) return;
			$this->blocks($ctx, $ctx[0], 0, 16);
			$ctx[1] = 0;
		}

		if ($bytes >= 16) {
			$want = ($bytes & ~(16 - 1));
			$this->blocks($ctx, $m, $mpos, $want);
			$mpos  += $want;
			$bytes -= $want;
		}

		if ($bytes) {
			for ($i = $bytes; $i--;) {
				$ctx[0][$ctx[1]+$i] = $m[$i+$mpos];
			}
			$ctx[1] += $bytes;
		}
	}

	public function finish($ctx, $mac) {
		$g = new SplFixedArray(10);

		if ($ctx[1]) {
			$i = $ctx[1];
			$ctx[0][$i++] = 1;
			for (; $i < 16; $i++)
				$ctx[0][$i] = 0;
			$ctx[5] = 1;
			$this->blocks($ctx, $ctx[0], 0, 16);
		}

		$c = $ctx[3][1] >> 13;
		$ctx[3][1] &= 0x1fff;
		for ($i = 2; $i < 10; $i++) {
			$ctx[3][$i] += $c;
			$c = $ctx[3][$i] >> 13;
			$ctx[3][$i] &= 0x1fff;
		}
		$ctx[3][0] += ($c * 5);
		$c = $ctx[3][0] >> 13;
		$ctx[3][0] &= 0x1fff;
		$ctx[3][1] += $c;
		$c = $ctx[3][1] >> 13;
		$ctx[3][1] &= 0x1fff;
		$ctx[3][2] += $c;
	 
		$g[0] = $ctx[3][0] + 5;
		$c = $g[0] >> 13;
		$g[0] &= 0x1fff;
		for ($i = 1; $i < 10; $i++) {
			$g[$i] = $ctx[3][$i] + $c;
			$c = $g[$i] >> 13;
			$g[$i] &= 0x1fff;
		}
		$g[9] -= (1 << 13);
		$g[9] &= 0xffff;

		$mask = ($g[9] >> 15) - 1;
		for ($i = 10; $i--;) $g[$i] &= $mask;
		$mask = ~$mask;
		for ($i = 10; $i--;) $ctx[3][$i] = ($ctx[3][$i] & $mask) | $g[$i];

		$ctx[3][0] = (($ctx[3][0]      ) | ($ctx[3][1] << 13)) & 0xffff;
		$ctx[3][1] = (($ctx[3][1] >>  3) | ($ctx[3][2] << 10)) & 0xffff;
		$ctx[3][2] = (($ctx[3][2] >>  6) | ($ctx[3][3] <<  7)) & 0xffff;
		$ctx[3][3] = (($ctx[3][3] >>  9) | ($ctx[3][4] <<  4)) & 0xffff;
		$ctx[3][4] = (($ctx[3][4] >> 12) | ($ctx[3][5] <<  1) | ($ctx[3][6] << 14)) & 0xffff;
		$ctx[3][5] = (($ctx[3][6] >>  2) | ($ctx[3][7] << 11)) & 0xffff;
		$ctx[3][6] = (($ctx[3][7] >>  5) | ($ctx[3][8] <<  8)) & 0xffff;
		$ctx[3][7] = (($ctx[3][8] >>  8) | ($ctx[3][9] <<  5)) & 0xffff;

		$f = ($ctx[3][0] & 0xffffffff) + $ctx[4][0];
		$ctx[3][0] = $f & 0xffff;
		for ($i = 1; $i < 8; $i++) {
			$f = ($ctx[3][$i] & 0xffffffff) + $ctx[4][$i] + ($f >> 16);
			$ctx[3][$i] = $f & 0xffff;
		}

		for ($i = 8; $i--;) {
			$this->U16TO8($mac, $i*2, $ctx[3][$i]);
			$ctx[4][$i] = 0;
		}
		for ($i = 10; $i--;) {
			$ctx[3][$i] = 0;
			$ctx[2][$i] = 0;
		}
	}

	protected static $_instance;

	public static function instance() {
		if (!isset(static::$_instance)) {
			static::$_instance = new Poly1305();
		}
		return static::$_instance;
	}

	public static function auth($mac, $m, $bytes, $key) {
		$p = Poly1305::instance();
		$ctx = $p->init($key);
		$p->update($ctx, $m, $bytes);
		$p->finish($ctx, $mac);
	}

}
