<?php
/**
 * Ed25519 - ref10
 *
 * Assembled from:
 *  - https://github.com/jedisct1/libsodium/
 *  - https://github.com/agl/ed25519/
 *
 * 
 * @link   https://github.com/devi/Salt
 * 
 */
class GeProjective {

	public $X;
	public $Y;
	public $Z;

	function __construct(){
		$this->X = new SplFixedArray(10);
		$this->Y = new SplFixedArray(10);
		$this->Z = new SplFixedArray(10);
	}
}

class GeExtended extends GeProjective {

	public $T;

	function __construct(){
		parent::__construct();
		$this->T = new SplFixedArray(10);
	}
}

class GeCompleted extends GeExtended {}

class GePrecomp {

	public $yplusx;
	public $yminusx;
	public $xy2d;

	function __construct($x = null, $y = null, $z = null) {
		$this->yplusx = $x ? SplFixedArray::fromArray($x) : new SplFixedArray(10);
		$this->yminusx = $y ? SplFixedArray::fromArray($y) :new SplFixedArray(10);
		$this->xy2d = $z ? SplFixedArray::fromArray($z) :new SplFixedArray(10);
	}
}

class GeCached {

	public $YplusX;
	public $YminusX;
	public $Z;
	public $T2d;

	function __construct() {
		$this->YplusX = new SplFixedArray(10);
		$this->YminusX = new SplFixedArray(10);
		$this->Z = new SplFixedArray(10);
		$this->T2d = new SplFixedArray(10);
	}

}

class Ed25519 {

	// lazy load
	protected static $instance;

	public static function instance() {
		if (!isset(static::$instance))
			static::$instance = new Ed25519();
		return static::$instance;
	}

	protected static $base;
	protected static $Bi;

	function __construct() {
		// TODO: simplified
		if (!isset(static::$base)) {
			static::$base = new SplFixedArray(32);
			$const = SplFixedArray::fromArray((include "base.php"), false);
			for ($i = 0;$i < 32;++$i) {
				static::$base[$i] = new SplFixedArray(8);
				for ($j = 0;$j < 8;++$j) {
					static::$base[$i][$j] = new GePrecomp(
						$const[$i][$j][0],
						$const[$i][$j][1],
						$const[$i][$j][2]
					);
				}
			}
		}
		if (!isset(static::$Bi)) {
			static::$Bi = new SplFixedArray(8);
			$const = SplFixedArray::fromArray((include "base2.php"), false);
			 for ($i = 0;$i < 8;++$i) {
				static::$Bi[$i] = new GePrecomp(
					$const[$i][0],
					$const[$i][1],
					$const[$i][2]
				);
			}
		}
	}

	function feZero($h) {
		for ($i = 0;$i < 10;++$i) {
			$h[$i] = 0;
		}
	}

	function feOne($h) {
		$this->feZero($h);
		$h[0] = 1;
	}

	function feAdd($h, $f, $g) {
		for ($i = 0;$i < 10;++$i) {
			$h[$i] = $f[$i] + $g[$i];
		}
	}

	function feCMove($f, $g, $b) {
		$b = -$b;
		for ($i = 0;$i < 10;++$i) {
			$x = $b & ($f[$i] ^ $g[$i]);
			$f[$i] ^= $x;
		}
	}

	function feCopy($h, $f) {
		for ($i = 0;$i < 10;++$i) {
			$h[$i] = $f[$i];
		}
	}

	function feSub($h, $f, $g) {
		for ($i = 0;$i < 10;++$i) {
			$h[$i] = $f[$i] - $g[$i];
		}
	}

	function feLoad3($in, $pos) {
		$result = $in[$pos];
		$result |= $in[1+$pos] << 8;
		$result |= $in[2+$pos] << 16;
		return $result;
	}

	function feLoad4($in, $pos) {
		$result = $in[$pos];
		$result |= $in[1+$pos] << 8;
		$result |= $in[2+$pos] << 16;
		$result |= $in[3+$pos] << 24;
		return $result;
	}

	function feFromBytes($h, $s) {
		$h0 = $this->feLoad4($s,  0);
		$h1 = $this->feLoad3($s,  4) << 6;
		$h2 = $this->feLoad3($s,  7) << 5;
		$h3 = $this->feLoad3($s, 10) << 3;
		$h4 = $this->feLoad3($s, 13) << 2;
		$h5 = $this->feLoad4($s, 16);
		$h6 = $this->feLoad3($s, 20) << 7;
		$h7 = $this->feLoad3($s, 23) << 5;
		$h8 = $this->feLoad3($s, 26) << 4;
		$h9 = ($this->feLoad3($s,29) & 8388607) << 2;

		$carry9 = ($h9 +  (1<<24)) >> 25; $h0 += $carry9 * 19; $h9 -= $carry9 << 25;
		$carry1 = ($h1 +  (1<<24)) >> 25; $h2 += $carry1; $h1 -= $carry1 << 25;
		$carry3 = ($h3 +  (1<<24)) >> 25; $h4 += $carry3; $h3 -= $carry3 << 25;
		$carry5 = ($h5 +  (1<<24)) >> 25; $h6 += $carry5; $h5 -= $carry5 << 25;
		$carry7 = ($h7 +  (1<<24)) >> 25; $h8 += $carry7; $h7 -= $carry7 << 25;

		$carry0 = ($h0 +  (1<<25)) >> 26; $h1 += $carry0; $h0 -= $carry0 << 26;
		$carry2 = ($h2 +  (1<<25)) >> 26; $h3 += $carry2; $h2 -= $carry2 << 26;
		$carry4 = ($h4 +  (1<<25)) >> 26; $h5 += $carry4; $h4 -= $carry4 << 26;
		$carry6 = ($h6 +  (1<<25)) >> 26; $h7 += $carry6; $h6 -= $carry6 << 26;
		$carry8 = ($h8 +  (1<<25)) >> 26; $h9 += $carry8; $h8 -= $carry8 << 26;

		$h[0] = $h0;
		$h[1] = $h1;
		$h[2] = $h2;
		$h[3] = $h3;
		$h[4] = $h4;
		$h[5] = $h5;
		$h[6] = $h6;
		$h[7] = $h7;
		$h[8] = $h8;
		$h[9] = $h9;
	}

	function feToBytes($s, $h) {
		$q = (19 * $h[9] + (1 << 24)) >> 25;
		$q = ($h[0] + $q) >> 26;
		$q = ($h[1] + $q) >> 25;
		$q = ($h[2] + $q) >> 26;
		$q = ($h[3] + $q) >> 25;
		$q = ($h[4] + $q) >> 26;
		$q = ($h[5] + $q) >> 25;
		$q = ($h[6] + $q) >> 26;
		$q = ($h[7] + $q) >> 25;
		$q = ($h[8] + $q) >> 26;
		$q = ($h[9] + $q) >> 25;

		$h[0] += 19 * $q;

		$carry0 = $h[0] >> 26; $h[1] += $carry0; $h[0] -= $carry0 << 26;
		$carry1 = $h[1] >> 25; $h[2] += $carry1; $h[1] -= $carry1 << 25;
		$carry2 = $h[2] >> 26; $h[3] += $carry2; $h[2] -= $carry2 << 26;
		$carry3 = $h[3] >> 25; $h[4] += $carry3; $h[3] -= $carry3 << 25;
		$carry4 = $h[4] >> 26; $h[5] += $carry4; $h[4] -= $carry4 << 26;
		$carry5 = $h[5] >> 25; $h[6] += $carry5; $h[5] -= $carry5 << 25;
		$carry6 = $h[6] >> 26; $h[7] += $carry6; $h[6] -= $carry6 << 26;
		$carry7 = $h[7] >> 25; $h[8] += $carry7; $h[7] -= $carry7 << 25;
		$carry8 = $h[8] >> 26; $h[9] += $carry8; $h[8] -= $carry8 << 26;
		$carry9 = $h[9] >> 25;                 $h[9] -= $carry9 << 25;

		$s[0] = ($h[0] >> 0) & 0xff;
		$s[1] = ($h[0] >> 8) & 0xff;
		$s[2] = ($h[0] >> 16) & 0xff;
		$s[3] = (($h[0] >> 24) | ($h[1] << 2)) & 0xff;
		$s[4] = ($h[1] >> 6) & 0xff;
		$s[5] = ($h[1] >> 14) & 0xff;
		$s[6] = (($h[1] >> 22) | ($h[2] << 3)) & 0xff;
		$s[7] = ($h[2] >> 5) & 0xff;
		$s[8] = ($h[2] >> 13) & 0xff;
		$s[9] = (($h[2] >> 21) | ($h[3] << 5)) & 0xff;
		$s[10] = ($h[3] >> 3) & 0xff;
		$s[11] = ($h[3] >> 11) & 0xff;
		$s[12] = (($h[3] >> 19) | ($h[4] << 6)) & 0xff;
		$s[13] = ($h[4] >> 2) & 0xff;
		$s[14] = ($h[4] >> 10) & 0xff;
		$s[15] = ($h[4] >> 18) & 0xff;
		$s[16] = ($h[5] >> 0) & 0xff;
		$s[17] = ($h[5] >> 8) & 0xff;
		$s[18] = ($h[5] >> 16) & 0xff;
		$s[19] = (($h[5] >> 24) | ($h[6] << 1)) & 0xff;
		$s[20] = ($h[6] >> 7) & 0xff;
		$s[21] = ($h[6] >> 15) & 0xff;
		$s[22] = (($h[6] >> 23) | ($h[7] << 3)) & 0xff;
		$s[23] = ($h[7] >> 5) & 0xff;
		$s[24] = ($h[7] >> 13) & 0xff;
		$s[25] = (($h[7] >> 21) | ($h[8] << 4)) & 0xff;
		$s[26] = ($h[8] >> 4) & 0xff;
		$s[27] = ($h[8] >> 12) & 0xff;
		$s[28] = (($h[8] >> 20) | ($h[9] << 6)) & 0xff;
		$s[29] = ($h[9] >> 2) & 0xff;
		$s[30] = ($h[9] >> 10) & 0xff;
		$s[31] = ($h[9] >> 18) & 0xff;
	}

	function feMul($h, $f, $g) {
		$f0 = $f[0];
		$f1 = $f[1];
		$f2 = $f[2];
		$f3 = $f[3];
		$f4 = $f[4];
		$f5 = $f[5];
		$f6 = $f[6];
		$f7 = $f[7];
		$f8 = $f[8];
		$f9 = $f[9];
		$g0 = $g[0];
		$g1 = $g[1];
		$g2 = $g[2];
		$g3 = $g[3];
		$g4 = $g[4];
		$g5 = $g[5];
		$g6 = $g[6];
		$g7 = $g[7];
		$g8 = $g[8];
		$g9 = $g[9];
		$g1_19 = 19 * $g1;
		$g2_19 = 19 * $g2;
		$g3_19 = 19 * $g3;
		$g4_19 = 19 * $g4;
		$g5_19 = 19 * $g5;
		$g6_19 = 19 * $g6;
		$g7_19 = 19 * $g7;
		$g8_19 = 19 * $g8;
		$g9_19 = 19 * $g9;
		$f1_2 = 2 * $f1;
		$f3_2 = 2 * $f3;
		$f5_2 = 2 * $f5;
		$f7_2 = 2 * $f7;
		$f9_2 = 2 * $f9;
		$f0g0    = $f0   * $g0;
		$f0g1    = $f0   * $g1;
		$f0g2    = $f0   * $g2;
		$f0g3    = $f0   * $g3;
		$f0g4    = $f0   * $g4;
		$f0g5    = $f0   * $g5;
		$f0g6    = $f0   * $g6;
		$f0g7    = $f0   * $g7;
		$f0g8    = $f0   * $g8;
		$f0g9    = $f0   * $g9;
		$f1g0    = $f1   * $g0;
		$f1g1_2  = $f1_2 * $g1;
		$f1g2    = $f1   * $g2;
		$f1g3_2  = $f1_2 * $g3;
		$f1g4    = $f1   * $g4;
		$f1g5_2  = $f1_2 * $g5;
		$f1g6    = $f1   * $g6;
		$f1g7_2  = $f1_2 * $g7;
		$f1g8    = $f1   * $g8;
		$f1g9_38 = $f1_2 * $g9_19;
		$f2g0    = $f2   * $g0;
		$f2g1    = $f2   * $g1;
		$f2g2    = $f2   * $g2;
		$f2g3    = $f2   * $g3;
		$f2g4    = $f2   * $g4;
		$f2g5    = $f2   * $g5;
		$f2g6    = $f2   * $g6;
		$f2g7    = $f2   * $g7;
		$f2g8_19 = $f2   * $g8_19;
		$f2g9_19 = $f2   * $g9_19;
		$f3g0    = $f3   * $g0;
		$f3g1_2  = $f3_2 * $g1;
		$f3g2    = $f3   * $g2;
		$f3g3_2  = $f3_2 * $g3;
		$f3g4    = $f3   * $g4;
		$f3g5_2  = $f3_2 * $g5;
		$f3g6    = $f3   * $g6;
		$f3g7_38 = $f3_2 * $g7_19;
		$f3g8_19 = $f3   * $g8_19;
		$f3g9_38 = $f3_2 * $g9_19;
		$f4g0    = $f4   * $g0;
		$f4g1    = $f4   * $g1;
		$f4g2    = $f4   * $g2;
		$f4g3    = $f4   * $g3;
		$f4g4    = $f4   * $g4;
		$f4g5    = $f4   * $g5;
		$f4g6_19 = $f4   * $g6_19;
		$f4g7_19 = $f4   * $g7_19;
		$f4g8_19 = $f4   * $g8_19;
		$f4g9_19 = $f4   * $g9_19;
		$f5g0    = $f5   * $g0;
		$f5g1_2  = $f5_2 * $g1;
		$f5g2    = $f5   * $g2;
		$f5g3_2  = $f5_2 * $g3;
		$f5g4    = $f5   * $g4;
		$f5g5_38 = $f5_2 * $g5_19;
		$f5g6_19 = $f5   * $g6_19;
		$f5g7_38 = $f5_2 * $g7_19;
		$f5g8_19 = $f5   * $g8_19;
		$f5g9_38 = $f5_2 * $g9_19;
		$f6g0    = $f6   * $g0;
		$f6g1    = $f6   * $g1;
		$f6g2    = $f6   * $g2;
		$f6g3    = $f6   * $g3;
		$f6g4_19 = $f6   * $g4_19;
		$f6g5_19 = $f6   * $g5_19;
		$f6g6_19 = $f6   * $g6_19;
		$f6g7_19 = $f6   * $g7_19;
		$f6g8_19 = $f6   * $g8_19;
		$f6g9_19 = $f6   * $g9_19;
		$f7g0    = $f7   * $g0;
		$f7g1_2  = $f7_2 * $g1;
		$f7g2    = $f7   * $g2;
		$f7g3_38 = $f7_2 * $g3_19;
		$f7g4_19 = $f7   * $g4_19;
		$f7g5_38 = $f7_2 * $g5_19;
		$f7g6_19 = $f7   * $g6_19;
		$f7g7_38 = $f7_2 * $g7_19;
		$f7g8_19 = $f7   * $g8_19;
		$f7g9_38 = $f7_2 * $g9_19;
		$f8g0    = $f8   * $g0;
		$f8g1    = $f8   * $g1;
		$f8g2_19 = $f8   * $g2_19;
		$f8g3_19 = $f8   * $g3_19;
		$f8g4_19 = $f8   * $g4_19;
		$f8g5_19 = $f8   * $g5_19;
		$f8g6_19 = $f8   * $g6_19;
		$f8g7_19 = $f8   * $g7_19;
		$f8g8_19 = $f8   * $g8_19;
		$f8g9_19 = $f8   * $g9_19;
		$f9g0    = $f9   * $g0;
		$f9g1_38 = $f9_2 * $g1_19;
		$f9g2_19 = $f9   * $g2_19;
		$f9g3_38 = $f9_2 * $g3_19;
		$f9g4_19 = $f9   * $g4_19;
		$f9g5_38 = $f9_2 * $g5_19;
		$f9g6_19 = $f9   * $g6_19;
		$f9g7_38 = $f9_2 * $g7_19;
		$f9g8_19 = $f9   * $g8_19;
		$f9g9_38 = $f9_2 * $g9_19;
		$h0 = $f0g0 + $f1g9_38 + $f2g8_19 + $f3g7_38 + $f4g6_19 + $f5g5_38 + $f6g4_19 + $f7g3_38 + $f8g2_19 + $f9g1_38;
		$h1 = $f0g1 + $f1g0    + $f2g9_19 + $f3g8_19 + $f4g7_19 + $f5g6_19 + $f6g5_19 + $f7g4_19 + $f8g3_19 + $f9g2_19;
		$h2 = $f0g2 + $f1g1_2  + $f2g0    + $f3g9_38 + $f4g8_19 + $f5g7_38 + $f6g6_19 + $f7g5_38 + $f8g4_19 + $f9g3_38;
		$h3 = $f0g3 + $f1g2    + $f2g1    + $f3g0    + $f4g9_19 + $f5g8_19 + $f6g7_19 + $f7g6_19 + $f8g5_19 + $f9g4_19;
		$h4 = $f0g4 + $f1g3_2  + $f2g2    + $f3g1_2  + $f4g0    + $f5g9_38 + $f6g8_19 + $f7g7_38 + $f8g6_19 + $f9g5_38;
		$h5 = $f0g5 + $f1g4    + $f2g3    + $f3g2    + $f4g1    + $f5g0    + $f6g9_19 + $f7g8_19 + $f8g7_19 + $f9g6_19;
		$h6 = $f0g6 + $f1g5_2  + $f2g4    + $f3g3_2  + $f4g2    + $f5g1_2  + $f6g0    + $f7g9_38 + $f8g8_19 + $f9g7_38;
		$h7 = $f0g7 + $f1g6    + $f2g5    + $f3g4    + $f4g3    + $f5g2    + $f6g1    + $f7g0    + $f8g9_19 + $f9g8_19;
		$h8 = $f0g8 + $f1g7_2  + $f2g6    + $f3g5_2  + $f4g4    + $f5g3_2  + $f6g2    + $f7g1_2  + $f8g0    + $f9g9_38;
		$h9 = $f0g9 + $f1g8    + $f2g7    + $f3g6    + $f4g5    + $f5g4    + $f6g3    + $f7g2    + $f8g1    + $f9g0   ;

		$carry0 = ($h0 + (1<<25)) >> 26; $h1 += $carry0; $h0 -= $carry0 << 26;
		$carry4 = ($h4 + (1<<25)) >> 26; $h5 += $carry4; $h4 -= $carry4 << 26;

		$carry1 = ($h1 + (1<<24)) >> 25; $h2 += $carry1; $h1 -= $carry1 << 25;
		$carry5 = ($h5 + (1<<24)) >> 25; $h6 += $carry5; $h5 -= $carry5 << 25;

		$carry2 = ($h2 + (1<<25)) >> 26; $h3 += $carry2; $h2 -= $carry2 << 26;
		$carry6 = ($h6 + (1<<25)) >> 26; $h7 += $carry6; $h6 -= $carry6 << 26;

		$carry3 = ($h3 + (1<<24)) >> 25; $h4 += $carry3; $h3 -= $carry3 << 25;
		$carry7 = ($h7 + (1<<24)) >> 25; $h8 += $carry7; $h7 -= $carry7 << 25;

		$carry4 = ($h4 + (1<<25)) >> 26; $h5 += $carry4; $h4 -= $carry4 << 26;
		$carry8 = ($h8 + (1<<25)) >> 26; $h9 += $carry8; $h8 -= $carry8 << 26;

		$carry9 = ($h9 + (1<<24)) >> 25; $h0 += $carry9 * 19; $h9 -= $carry9 << 25;

		$carry0 = ($h0 + (1<<25)) >> 26; $h1 += $carry0; $h0 -= $carry0 << 26;

		$h[0] = $h0;
		$h[1] = $h1;
		$h[2] = $h2;
		$h[3] = $h3;
		$h[4] = $h4;
		$h[5] = $h5;
		$h[6] = $h6;
		$h[7] = $h7;
		$h[8] = $h8;
		$h[9] = $h9;
	}

	function feSquare($h, $f) {
		$f0 = $f[0];
		$f1 = $f[1];
		$f2 = $f[2];
		$f3 = $f[3];
		$f4 = $f[4];
		$f5 = $f[5];
		$f6 = $f[6];
		$f7 = $f[7];
		$f8 = $f[8];
		$f9 = $f[9];
		$f0_2 = 2 * $f0;
		$f1_2 = 2 * $f1;
		$f2_2 = 2 * $f2;
		$f3_2 = 2 * $f3;
		$f4_2 = 2 * $f4;
		$f5_2 = 2 * $f5;
		$f6_2 = 2 * $f6;
		$f7_2 = 2 * $f7;
		$f5_38 = 38 * $f5;
		$f6_19 = 19 * $f6;
		$f7_38 = 38 * $f7;
		$f8_19 = 19 * $f8;
		$f9_38 = 38 * $f9;
		$f0f0    = $f0   * $f0;
		$f0f1_2  = $f0_2 * $f1;
		$f0f2_2  = $f0_2 * $f2;
		$f0f3_2  = $f0_2 * $f3;
		$f0f4_2  = $f0_2 * $f4;
		$f0f5_2  = $f0_2 * $f5;
		$f0f6_2  = $f0_2 * $f6;
		$f0f7_2  = $f0_2 * $f7;
		$f0f8_2  = $f0_2 * $f8;
		$f0f9_2  = $f0_2 * $f9;
		$f1f1_2  = $f1_2 * $f1;
		$f1f2_2  = $f1_2 * $f2;
		$f1f3_4  = $f1_2 * $f3_2;
		$f1f4_2  = $f1_2 * $f4;
		$f1f5_4  = $f1_2 * $f5_2;
		$f1f6_2  = $f1_2 * $f6;
		$f1f7_4  = $f1_2 * $f7_2;
		$f1f8_2  = $f1_2 * $f8;
		$f1f9_76 = $f1_2 * $f9_38;
		$f2f2    = $f2   * $f2;
		$f2f3_2  = $f2_2 * $f3;
		$f2f4_2  = $f2_2 * $f4;
		$f2f5_2  = $f2_2 * $f5;
		$f2f6_2  = $f2_2 * $f6;
		$f2f7_2  = $f2_2 * $f7;
		$f2f8_38 = $f2_2 * $f8_19;
		$f2f9_38 = $f2   * $f9_38;
		$f3f3_2  = $f3_2 * $f3;
		$f3f4_2  = $f3_2 * $f4;
		$f3f5_4  = $f3_2 * $f5_2;
		$f3f6_2  = $f3_2 * $f6;
		$f3f7_76 = $f3_2 * $f7_38;
		$f3f8_38 = $f3_2 * $f8_19;
		$f3f9_76 = $f3_2 * $f9_38;
		$f4f4    = $f4   * $f4;
		$f4f5_2  = $f4_2 * $f5;
		$f4f6_38 = $f4_2 * $f6_19;
		$f4f7_38 = $f4   * $f7_38;
		$f4f8_38 = $f4_2 * $f8_19;
		$f4f9_38 = $f4   * $f9_38;
		$f5f5_38 = $f5   * $f5_38;
		$f5f6_38 = $f5_2 * $f6_19;
		$f5f7_76 = $f5_2 * $f7_38;
		$f5f8_38 = $f5_2 * $f8_19;
		$f5f9_76 = $f5_2 * $f9_38;
		$f6f6_19 = $f6   * $f6_19;
		$f6f7_38 = $f6   * $f7_38;
		$f6f8_38 = $f6_2 * $f8_19;
		$f6f9_38 = $f6   * $f9_38;
		$f7f7_38 = $f7   * $f7_38;
		$f7f8_38 = $f7_2 * $f8_19;
		$f7f9_76 = $f7_2 * $f9_38;
		$f8f8_19 = $f8   * $f8_19;
		$f8f9_38 = $f8   * $f9_38;
		$f9f9_38 = $f9   * $f9_38;
		$h0 = $f0f0   + $f1f9_76 + $f2f8_38 + $f3f7_76 + $f4f6_38 + $f5f5_38;
		$h1 = $f0f1_2 + $f2f9_38 + $f3f8_38 + $f4f7_38 + $f5f6_38;
		$h2 = $f0f2_2 + $f1f1_2  + $f3f9_76 + $f4f8_38 + $f5f7_76 + $f6f6_19;
		$h3 = $f0f3_2 + $f1f2_2  + $f4f9_38 + $f5f8_38 + $f6f7_38;
		$h4 = $f0f4_2 + $f1f3_4  + $f2f2    + $f5f9_76 + $f6f8_38 + $f7f7_38;
		$h5 = $f0f5_2 + $f1f4_2  + $f2f3_2  + $f6f9_38 + $f7f8_38;
		$h6 = $f0f6_2 + $f1f5_4  + $f2f4_2  + $f3f3_2  + $f7f9_76 + $f8f8_19;
		$h7 = $f0f7_2 + $f1f6_2  + $f2f5_2  + $f3f4_2  + $f8f9_38;
		$h8 = $f0f8_2 + $f1f7_4  + $f2f6_2  + $f3f5_4  + $f4f4    + $f9f9_38;
		$h9 = $f0f9_2 + $f1f8_2  + $f2f7_2  + $f3f6_2  + $f4f5_2;

		$carry0 = ($h0 + (1<<25)) >> 26; $h1 += $carry0; $h0 -= $carry0 << 26;
		$carry4 = ($h4 + (1<<25)) >> 26; $h5 += $carry4; $h4 -= $carry4 << 26;

		$carry1 = ($h1 + (1<<24)) >> 25; $h2 += $carry1; $h1 -= $carry1 << 25;
		$carry5 = ($h5 + (1<<24)) >> 25; $h6 += $carry5; $h5 -= $carry5 << 25;

		$carry2 = ($h2 + (1<<25)) >> 26; $h3 += $carry2; $h2 -= $carry2 << 26;
		$carry6 = ($h6 + (1<<25)) >> 26; $h7 += $carry6; $h6 -= $carry6 << 26;

		$carry3 = ($h3 + (1<<24)) >> 25; $h4 += $carry3; $h3 -= $carry3 << 25;
		$carry7 = ($h7 + (1<<24)) >> 25; $h8 += $carry7; $h7 -= $carry7 << 25;

		$carry4 = ($h4 + (1<<25)) >> 26; $h5 += $carry4; $h4 -= $carry4 << 26;
		$carry8 = ($h8 + (1<<25)) >> 26; $h9 += $carry8; $h8 -= $carry8 << 26;

		$carry9 = ($h9 + (1<<24)) >> 25; $h0 += $carry9 * 19; $h9 -= $carry9 << 25;

		$carry0 = ($h0 + (1<<25)) >> 26; $h1 += $carry0; $h0 -= $carry0 << 26;

		$h[0] = $h0;
		$h[1] = $h1;
		$h[2] = $h2;
		$h[3] = $h3;
		$h[4] = $h4;
		$h[5] = $h5;
		$h[6] = $h6;
		$h[7] = $h7;
		$h[8] = $h8;
		$h[9] = $h9;
	}

	function feInvert($out, $z) {
		$t0 = new SplFixedArray(10);
		$t1 = new SplFixedArray(10);
		$t2 = new SplFixedArray(10);
		$t3 = new SplFixedArray(10);

		/* pow225521 */
		$this->feSquare($t0, $z);
		for ($i = 1;$i < 1;++$i) {
			$this->feSquare($t0, $t0);
		}
		$this->feSquare($t1, $t0);
		for ($i = 1;$i < 2;++$i) {
			$this->feSquare($t1, $t1);
		}
		$this->feMul($t1, $z, $t1);
		$this->feMul($t0, $t0, $t1);
		$this->feSquare($t2, $t0);
		for ($i = 1;$i < 1;++$i) {
			$this->feSquare($t2, $t2);
		}
		$this->feMul($t1, $t1, $t2);
		$this->feSquare($t2, $t1);
		for ($i = 1;$i < 5;++$i) {
			$this->feSquare($t2, $t2);
		}
		$this->feMul($t1, $t2, $t1);
		$this->feSquare($t2, $t1);
		for ($i = 1;$i < 10;++$i) {
			$this->feSquare($t2, $t2);
		}
		$this->feMul($t2, $t2, $t1);
		$this->feSquare($t3, $t2);
		for ($i = 1;$i < 20;++$i) {
			$this->feSquare($t3, $t3);
		}
		$this->feMul($t2, $t3, $t2);
		$this->feSquare($t2, $t2);
		for ($i = 1;$i < 10;++$i) {
			$this->feSquare($t2, $t2);
		}
		$this->feMul($t1, $t2, $t1);
		$this->feSquare($t2, $t1);
		for ($i = 1;$i < 50;++$i) {
			$this->feSquare($t2, $t2);
		}
		$this->feMul($t2, $t2, $t1);
		$this->feSquare($t3, $t2);
		for ($i = 1;$i < 100;++$i) {
			$this->feSquare($t3, $t3);
		}
		$this->feMul($t2, $t3, $t2);
		$this->feSquare($t2, $t2);
		for ($i = 1;$i < 50;++$i) {
			$this->feSquare($t2, $t2);
		}
		$this->feMul($t1, $t2, $t1);
		$this->feSquare($t1, $t1);
		for ($i = 1;$i < 5;++$i) {
			$this->feSquare($t1, $t1);
		}
		$this->feMul($out, $t1, $t0);
	}

	function feSquare2($h, $f) {
		$f0 = $f[0];
		$f1 = $f[1];
		$f2 = $f[2];
		$f3 = $f[3];
		$f4 = $f[4];
		$f5 = $f[5];
		$f6 = $f[6];
		$f7 = $f[7];
		$f8 = $f[8];
		$f9 = $f[9];
		$f0_2 = 2 * $f0;
		$f1_2 = 2 * $f1;
		$f2_2 = 2 * $f2;
		$f3_2 = 2 * $f3;
		$f4_2 = 2 * $f4;
		$f5_2 = 2 * $f5;
		$f6_2 = 2 * $f6;
		$f7_2 = 2 * $f7;
		$f5_38 = 38 * $f5;
		$f6_19 = 19 * $f6;
		$f7_38 = 38 * $f7;
		$f8_19 = 19 * $f8;
		$f9_38 = 38 * $f9;
		$f0f0    = $f0   * $f0;
		$f0f1_2  = $f0_2 * $f1;
		$f0f2_2  = $f0_2 * $f2;
		$f0f3_2  = $f0_2 * $f3;
		$f0f4_2  = $f0_2 * $f4;
		$f0f5_2  = $f0_2 * $f5;
		$f0f6_2  = $f0_2 * $f6;
		$f0f7_2  = $f0_2 * $f7;
		$f0f8_2  = $f0_2 * $f8;
		$f0f9_2  = $f0_2 * $f9;
		$f1f1_2  = $f1_2 * $f1;
		$f1f2_2  = $f1_2 * $f2;
		$f1f3_4  = $f1_2 * $f3_2;
		$f1f4_2  = $f1_2 * $f4;
		$f1f5_4  = $f1_2 * $f5_2;
		$f1f6_2  = $f1_2 * $f6;
		$f1f7_4  = $f1_2 * $f7_2;
		$f1f8_2  = $f1_2 * $f8;
		$f1f9_76 = $f1_2 * $f9_38;
		$f2f2    = $f2   * $f2;
		$f2f3_2  = $f2_2 * $f3;
		$f2f4_2  = $f2_2 * $f4;
		$f2f5_2  = $f2_2 * $f5;
		$f2f6_2  = $f2_2 * $f6;
		$f2f7_2  = $f2_2 * $f7;
		$f2f8_38 = $f2_2 * $f8_19;
		$f2f9_38 = $f2   * $f9_38;
		$f3f3_2  = $f3_2 * $f3;
		$f3f4_2  = $f3_2 * $f4;
		$f3f5_4  = $f3_2 * $f5_2;
		$f3f6_2  = $f3_2 * $f6;
		$f3f7_76 = $f3_2 * $f7_38;
		$f3f8_38 = $f3_2 * $f8_19;
		$f3f9_76 = $f3_2 * $f9_38;
		$f4f4    = $f4   * $f4;
		$f4f5_2  = $f4_2 * $f5;
		$f4f6_38 = $f4_2 * $f6_19;
		$f4f7_38 = $f4   * $f7_38;
		$f4f8_38 = $f4_2 * $f8_19;
		$f4f9_38 = $f4   * $f9_38;
		$f5f5_38 = $f5   * $f5_38;
		$f5f6_38 = $f5_2 * $f6_19;
		$f5f7_76 = $f5_2 * $f7_38;
		$f5f8_38 = $f5_2 * $f8_19;
		$f5f9_76 = $f5_2 * $f9_38;
		$f6f6_19 = $f6   * $f6_19;
		$f6f7_38 = $f6   * $f7_38;
		$f6f8_38 = $f6_2 * $f8_19;
		$f6f9_38 = $f6   * $f9_38;
		$f7f7_38 = $f7   * $f7_38;
		$f7f8_38 = $f7_2 * $f8_19;
		$f7f9_76 = $f7_2 * $f9_38;
		$f8f8_19 = $f8   * $f8_19;
		$f8f9_38 = $f8   * $f9_38;
		$f9f9_38 = $f9   * $f9_38;
		$h0 = $f0f0   + $f1f9_76 + $f2f8_38 + $f3f7_76 + $f4f6_38 + $f5f5_38;
		$h1 = $f0f1_2 + $f2f9_38 + $f3f8_38 + $f4f7_38 + $f5f6_38;
		$h2 = $f0f2_2 + $f1f1_2  + $f3f9_76 + $f4f8_38 + $f5f7_76 + $f6f6_19;
		$h3 = $f0f3_2 + $f1f2_2  + $f4f9_38 + $f5f8_38 + $f6f7_38;
		$h4 = $f0f4_2 + $f1f3_4  + $f2f2    + $f5f9_76 + $f6f8_38 + $f7f7_38;
		$h5 = $f0f5_2 + $f1f4_2  + $f2f3_2  + $f6f9_38 + $f7f8_38;
		$h6 = $f0f6_2 + $f1f5_4  + $f2f4_2  + $f3f3_2  + $f7f9_76 + $f8f8_19;
		$h7 = $f0f7_2 + $f1f6_2  + $f2f5_2  + $f3f4_2  + $f8f9_38;
		$h8 = $f0f8_2 + $f1f7_4  + $f2f6_2  + $f3f5_4  + $f4f4    + $f9f9_38;
		$h9 = $f0f9_2 + $f1f8_2  + $f2f7_2  + $f3f6_2  + $f4f5_2;

		$h0 += $h0;
		$h1 += $h1;
		$h2 += $h2;
		$h3 += $h3;
		$h4 += $h4;
		$h5 += $h5;
		$h6 += $h6;
		$h7 += $h7;
		$h8 += $h8;
		$h9 += $h9;

		$carry0 = ($h0 + (1<<25)) >> 26; $h1 += $carry0; $h0 -= $carry0 << 26;
		$carry4 = ($h4 + (1<<25)) >> 26; $h5 += $carry4; $h4 -= $carry4 << 26;

		$carry1 = ($h1 + (1<<24)) >> 25; $h2 += $carry1; $h1 -= $carry1 << 25;
		$carry5 = ($h5 + (1<<24)) >> 25; $h6 += $carry5; $h5 -= $carry5 << 25;

		$carry2 = ($h2 + (1<<25)) >> 26; $h3 += $carry2; $h2 -= $carry2 << 26;
		$carry6 = ($h6 + (1<<25)) >> 26; $h7 += $carry6; $h6 -= $carry6 << 26;

		$carry3 = ($h3 + (1<<24)) >> 25; $h4 += $carry3; $h3 -= $carry3 << 25;
		$carry7 = ($h7 + (1<<24)) >> 25; $h8 += $carry7; $h7 -= $carry7 << 25;

		$carry4 = ($h4 + (1<<25)) >> 26; $h5 += $carry4; $h4 -= $carry4 << 26;
		$carry8 = ($h8 + (1<<25)) >> 26; $h9 += $carry8; $h8 -= $carry8 << 26;

		$carry9 = ($h9 + (1<<24)) >> 25; $h0 += $carry9 * 19; $h9 -= $carry9 << 25;

		$carry0 = ($h0 + (1<<25)) >> 26; $h1 += $carry0; $h0 -= $carry0 << 26;

		$h[0] = $h0;
		$h[1] = $h1;
		$h[2] = $h2;
		$h[3] = $h3;
		$h[4] = $h4;
		$h[5] = $h5;
		$h[6] = $h6;
		$h[7] = $h7;
		$h[8] = $h8;
		$h[9] = $h9;
	}

	function feIsNegative($f) {
		$s = new SplFixedArray(32);
		$this->feToBytes($s, $f);
		return ($s[0] & 1);
	}

	function cryptoVerify32($x, $y) {
		$d = 0;
		for ($i = 0;$i < 32;++$i) {
			$d |= $x[$i] ^ $y[$i];
		}
		return (1 & (($d - 1) >> 8)) - 1;
	}

	function feIsNonZero($f) {
		$s = new SplFixedArray(32);
		$zero = new SplFixedArray(32);
		$this->feZero($zero);
		$this->feToBytes($s, $f);
		return $this->cryptoVerify32($s, $zero);
	}

	function feNegative($h, $f) {
		for ($i = 0;$i < 10;++$i) {
			$h[$i] = -$f[$i];
		}
	}

	function fePow22523($out, $z) {
		$t0 = new SplFixedArray(10);
		$t1 = new SplFixedArray(10);
		$t2 = new SplFixedArray(10);

		$this->feSquare($t0,$z);
		for ($i = 1;$i < 1;++$i) {
			$this->feSquare($t0,$t0);
		}
		$this->feSquare($t1,$t0);
		for ($i = 1;$i < 2;++$i) {
			$this->feSquare($t1,$t1);
		}
		$this->feMul($t1,$z,$t1);
		$this->feMul($t0,$t0,$t1);
		$this->feSquare($t0,$t0);
		for ($i = 1;$i < 1;++$i) {
			$this->feSquare($t0,$t0);
		}
		$this->feMul($t0,$t1,$t0);
		$this->feSquare($t1,$t0);
		for ($i = 1;$i < 5;++$i) {
			$this->feSquare($t1,$t1);
		}
		$this->feMul($t0,$t1,$t0);
		$this->feSquare($t1,$t0);
		for ($i = 1;$i < 10;++$i) {
			$this->feSquare($t1,$t1);
		}
		$this->feMul($t1,$t1,$t0);
		$this->feSquare($t2,$t1);
		for ($i = 1;$i < 20;++$i) {
			$this->feSquare($t2,$t2);
		}
		$this->feMul($t1,$t2,$t1);
		$this->feSquare($t1,$t1);
		for ($i = 1;$i < 10;++$i) {
			$this->feSquare($t1,$t1);
		}
		$this->feMul($t0,$t1,$t0);
		$this->feSquare($t1,$t0);
		for ($i = 1;$i < 50;++$i) {
			$this->feSquare($t1,$t1);
		}
		$this->feMul($t1,$t1,$t0);
		$this->feSquare($t2,$t1);
		for ($i = 1;$i < 100;++$i) {
			$this->feSquare($t2,$t2);
		}
		$this->feMul($t1,$t2,$t1);
		$this->feSquare($t1,$t1);
		for ($i = 1;$i < 50;++$i) {
			$this->feSquare($t1,$t1);
		}
		$this->feMul($t0,$t1,$t0);
		$this->feSquare($t0,$t0);
		for ($i = 1;$i < 2;++$i) {
			$this->feSquare($t0,$t0);
		}
		$this->feMul($out,$t0,$z);
	}

	function GeProjectiveZero(GeProjective $h) {
		$this->feZero($h->X);
		$this->feOne($h->Y);
		$this->feOne($h->Z);
	}

	function GeProjectiveDouble(GeCompleted $r, GeProjective $p) {
		$t0 = new SplFixedArray(10);
		$this->feSquare($r->X, $p->X);
		$this->feSquare($r->Z, $p->Y);
		$this->feSquare2($r->T, $p->Z);
		$this->feAdd($r->Y, $p->X, $p->Y);
		$this->feSquare($t0, $r->Y);
		$this->feAdd($r->Y, $r->Z, $r->X);
		$this->feSub($r->Z, $r->Z, $r->X);
		$this->feSub($r->X, $t0, $r->Y);
		$this->feSub($r->T, $r->T, $r->Z);
	}

	function GeExtendedZero(GeExtended $h) {
		$this->feZero($h->X);
		$this->feOne($h->Y);
		$this->feOne($h->Z);
		$this->feZero($h->T);
	}

	function GeExtendedtoGeProjective(GeProjective $r, GeExtended $p) {
		$this->feCopy($r->X, $p->X);
		$this->feCopy($r->Y, $p->Y);
		$this->feCopy($r->Z, $p->Z);
	}

	function GeExtendedDouble(GeCompleted $r, GeExtended $p) {
		$q = new GeProjective();
		$this->GeExtendedtoGeProjective($q, $p);
		$this->GeProjectiveDouble($r, $q);
	}

	function GeExtendedtoGeCached(GeCached $r, GeExtended $p) {
		$d2 = array(
			-21827239, -5839606, -30745221, 13898782, 229458,
			15978800, -12551817, -6495438, 29715968, 9444199
		);
		$this->feAdd($r->YplusX, $p->Y, $p->X);
		$this->feSub($r->YminusX, $p->Y, $p->X);
		$this->feCopy($r->Z, $p->Z);
		$this->feMul($r->T2d, $p->T, $d2);
	}

	function GeExtendedtoBytes($s, GeExtended $h) {
		$recip = new SplFixedArray(10);
		$x = new SplFixedArray(10);
		$y = new SplFixedArray(10);

		$this->feInvert($recip, $h->Z);
		$this->feMul($x, $h->X, $recip);
		$this->feMul($y, $h->Y, $recip);
		$this->feToBytes($s, $y);
		$s[31] ^= $this->feIsNegative($x) << 7;
	}

	function GeCompletedtoGeProjective(GeProjective $r, GeCompleted $p) {
		$this->feMul($r->X, $p->X, $p->T);
		$this->feMul($r->Y, $p->Y, $p->Z);
		$this->feMul($r->Z, $p->Z, $p->T);
	}

	function GeCompletedtoGeExtended(GeExtended $r, GeCompleted $p) {
		$this->feMul($r->X, $p->X, $p->T);
		$this->feMul($r->Y, $p->Y, $p->Z);
		$this->feMul($r->Z, $p->Z, $p->T);
		$this->feMul($r->T, $p->X, $p->Y);
	}

	function GePrecompZero(GePrecomp $h) {
		$this->feOne($h->yplusx);
		$this->feOne($h->yminusx);
		$this->feZero($h->xy2d);
	}

	function geAdd(GeCompleted $r, GeExtended $p, GeCached $q) {
		$t0 = new SplFixedArray(10);
		$this->feAdd($r->X, $p->Y, $p->X);
		$this->feSub($r->Y, $p->Y, $p->X);
		$this->feMul($r->Z, $r->X, $q->YplusX);
		$this->feMul($r->Y, $r->Y, $q->YminusX);
		$this->feMul($r->T, $q->T2d, $p->T);
		$this->feMul($r->X, $p->Z, $q->Z);
		$this->feAdd($t0, $r->X, $r->X);
		$this->feSub($r->X, $r->Z, $r->Y);
		$this->feAdd($r->Y, $r->Z, $r->Y);
		$this->feAdd($r->Z, $t0, $r->T);
		$this->feSub($r->T, $t0, $r->T);
	}

	function geMixedAdd(GeCompleted $r, GeExtended $p,  GePrecomp $q) {
		$t0 = new SplFixedArray(10);
		$this->feAdd($r->X, $p->Y, $p->X);
		$this->feSub($r->Y, $p->Y, $p->X);
		$this->feMul($r->Z, $r->X, $q->yplusx);
		$this->feMul($r->Y, $r->Y, $q->yminusx);
		$this->feMul($r->T, $q->xy2d, $p->T);
		$this->feAdd($t0, $p->Z, $p->Z);
		$this->feSub($r->X, $r->Z, $r->Y);
		$this->feAdd($r->Y, $r->Z, $r->Y);
		$this->feAdd($r->Z, $t0, $r->T);
		$this->feSub($r->T, $t0, $r->T);
	}

	function geSub(GeCompleted $r,GeExtended $p,GeCached $q) {
		$t0 = new SplFixedArray(10);
		$this->feAdd($r->X, $p->Y, $p->X);
		$this->feSub($r->Y, $p->Y, $p->X);
		$this->feMul($r->Z, $r->X, $q->YminusX);
		$this->feMul($r->Y, $r->Y, $q->YplusX);
		$this->feMul($r->T, $q->T2d, $p->T);
		$this->feMul($r->X, $p->Z, $q->Z);
		$this->feAdd($t0, $r->X, $r->X);
		$this->feSub($r->X, $r->Z, $r->Y);
		$this->feAdd($r->Y, $r->Z, $r->Y);
		$this->feSub($r->Z, $t0, $r->T);
		$this->feAdd($r->T, $t0, $r->T);
	}

	function geMixedSub(GeCompleted $r, GeExtended $p, GePrecomp $q) {
		$t0 = new SplFixedArray(10);
		$this->feAdd($r->X, $p->Y, $p->X);
		$this->feSub($r->Y, $p->Y, $p->X);
		$this->feMul($r->Z, $r->X, $q->yminusx);
		$this->feMul($r->Y, $r->Y, $q->yplusx);
		$this->feMul($r->T, $q->xy2d, $p->T);
		$this->feAdd($t0, $p->Z, $p->Z);
		$this->feSub($r->X, $r->Z, $r->Y);
		$this->feAdd($r->Y, $r->Z, $r->Y);
		$this->feSub($r->Z, $t0, $r->T);
		$this->feAdd($r->T, $t0, $r->T);
	}

	function geFromBytesNegateVartime(GeExtended $h,  $s) {
		$u = new SplFixedArray(10);
		$v = new SplFixedArray(10);
		$v3 = new SplFixedArray(10);
		$vxx = new SplFixedArray(10);
		$check = new SplFixedArray(10);
		$d = array(
			-10913610, 13857413, -15372611, 6949391, 114729,
			-8787816,-6275908,-3247719,-18696448,-12055116
		);
		$sqrtm1 = array(
			-32595792, -7943725, 9377950, 3500415, 12389472,
			-272473, -25146209, -2005654, 326686, 11406482
		);

		$this->feFromBytes($h->Y, $s);
		$this->feOne($h->Z);
		$this->feSquare($u, $h->Y);
		$this->feMul($v, $u, $d);
		$this->feSub($u, $u, $h->Z);
		$this->feAdd($v, $v, $h->Z);

		$this->feSquare($v3, $v);
		$this->feMul($v3, $v3, $v);
		$this->feSquare($h->X, $v3);
		$this->feMul($h->X, $h->X, $v);
		$this->feMul($h->X, $h->X, $u);

		$this->fePow22523($h->X, $h->X);
		$this->feMul($h->X, $h->X, $v3);
		$this->feMul($h->X, $h->X, $u);

		$tmpX = new SplFixedArray(32);
		$tmp2 = new SplFixedArray(32);

		$this->feSquare($vxx, $h->X);
		$this->feMul($vxx, $vxx, $v);
		$this->feSub($check, $vxx, $u);
		if ($this->feIsNonZero($check)) {
			$this->feAdd($check, $vxx, $u);
			if ($this->feIsNonZero($check)) {
				return false;
			}
			$this->feMul($h->X, $h->X, $sqrtm1);
			$this->feToBytes($tmpX, $h->X);
			for ($i = 0;$i < 32;++$i) {
				$tmp2[31-$i] = $tmpX[$i];
			}
		}

		if ($this->feIsNegative($h->X) == ($s[31] >> 7)) {
			$this->feNegative($h->X, $h->X);
		}
		$this->feMul($h->T, $h->X, $h->Y);
		return true;
	}

	function geToBytes($s, GeProjective $h) {
		$recip = new SplFixedArray(10);
		$x = new SplFixedArray(10);
		$y = new SplFixedArray(10);

		$this->feInvert($recip, $h->Z);
		$this->feMul($x, $h->X, $recip);
		$this->feMul($y, $h->Y, $recip);
		$this->feToBytes($s, $y);
		$s[31] ^= $this->feIsNegative($x) << 7;
	}

	// equal returns 1 if b == c and 0 otherwise.
	function equal($b, $c) {
		$x = ($b ^ $c);
		$x--;
		$x &= 0xffffffff;
		return ($x >> 31);
		
	}

	// negative returns 1 if b < 0 and 0 otherwise.
	function negative($b) {
		return ($b >> 31) & 1;
	}

	function cMove(GePrecomp $t, GePrecomp $u, $b) {
		$this->feCMove($t->yplusx, $u->yplusx, $b);
		$this->feCMove($t->yminusx, $u->yminusx, $b);
		$this->feCMove($t->xy2d, $u->xy2d, $b);
	}

	function select(GePrecomp $t, $pos, $b) {
		$minust = new GePrecomp();
		$bnegative = $this->negative($b);
		$babs = $b - (((-$bnegative) & $b) << 1);

		$this->GePrecompZero($t);
		for ($i = 0;$i < 8;++$i) {
			$this->cMove($t, static::$base[$pos][$i], $this->equal($babs, $i+1));
		}

		$this->feCopy($minust->yplusx, $t->yminusx);
		$this->feCopy($minust->yminusx, $t->yplusx);
		$this->feNegative($minust->xy2d, $t->xy2d);
		$this->cMove($t, $minust, $bnegative);
	}

	function geScalarmultBase(GeExtended $h, $a) {
		$e = new SplFixedArray(64);
		$r = new GeCompleted();
		$s = new GeProjective();
		$t = new GePrecomp();

		for ($i = 0;$i < 32;++$i) {
			$e[2 * $i] = $a[$i] & 15;
			$e[2 * $i + 1] = ($a[$i] >> 4) & 15;
		}

		$carry = 0;
		for ($i = 0;$i < 63;++$i) {
			$e[$i] += $carry;
			$carry = $e[$i] + 8;
			$carry >>= 4;
			$e[$i] -= $carry << 4;
		}
		$e[63] += $carry;

		$this->GeExtendedZero($h);

		for ($i = 1;$i < 64;$i += 2) {
			$this->select($t, $i / 2, $e[$i]);
			$this->geMixedAdd($r, $h, $t);
			$this->GeCompletedtoGeExtended($h, $r);
		}

		$this->GeExtendedDouble($r, $h);
		$this->GeCompletedtoGeProjective($s, $r);
		$this->GeProjectiveDouble($r, $s);
		$this->GeCompletedtoGeProjective($s, $r);
		$this->GeProjectiveDouble($r, $s);
		$this->GeCompletedtoGeProjective($s, $r);
		$this->GeProjectiveDouble($r, $s);
		$this->GeCompletedtoGeExtended($h, $r);

		for ($i = 0;$i < 64;$i += 2) {
			$this->select($t, $i / 2, $e[$i]);
			$this->geMixedAdd($r, $h, $t);
			$this->GeCompletedtoGeExtended($h, $r);
		}
	}

	function slide($r, $a) {
		for ($i = 0;$i < 256;++$i)
			$r[$i] = 1 & ($a[$i >> 3] >> ($i & 7));

		for ($i = 0;$i < 256;++$i) {
			if ($r[$i]) {
				for ($b = 1;$b <= 6 && $i + $b < 256;++$b) {
					if ($r[$i + $b]) {
						if ($r[$i] + ($r[$i + $b] << $b) <= 15) {
							$r[$i] += $r[$i + $b] << $b; $r[$i + $b] = 0;
						} else if ($r[$i] - ($r[$i + $b] << $b) >= -15) {
							$r[$i] -= $r[$i + $b] << $b;
							for ($k = $i + $b;$k < 256;++$k) {
								if (!$r[$k]) {
									$r[$k] = 1;
									break;
								}
								$r[$k] = 0;
							}
						} else
							break;
					}
				}
			}
		}
	}

	function geDoubleScalarmultVartime(GeProjective $r, $a, GeExtended $A, $b) {
		$aslide = new SplFixedArray(256);
		$bslide = new SplFixedArray(256);
		$t = new GeCompleted();
		$u = new GeExtended();
		$A2 = new GeExtended();
		$Ai = new SplFixedArray(8);

		for ($i = 0;$i < 8;++$i) $Ai[$i] = new GeCached();

		$this->slide($aslide, $a);
		$this->slide($bslide, $b);

		$this->GeExtendedtoGeCached($Ai[0], $A);
		$this->GeExtendedDouble($t, $A);
		$this->GeCompletedtoGeExtended($A2, $t);

		for ($i = 0;$i < 7;++$i) {
			$this->geAdd($t, $A2, $Ai[$i]);
			$this->GeCompletedtoGeExtended($u, $t);
			$this->GeExtendedtoGeCached($Ai[$i+1], $u);
		}

		$this->GeProjectiveZero($r);

		for ($i = 255;$i >= 0;--$i) {
			if ($aslide[$i] || $bslide[$i]) break;
		}

		for ($i = 255;$i >= 0;--$i) {
			$this->GeProjectiveDouble($t, $r);

			if ($aslide[$i] > 0) {
				$this->GeCompletedtoGeExtended($u, $t);
				$this->geAdd($t, $u, $Ai[$aslide[$i]/2]);
			} else if ($aslide[$i] < 0) {
				$this->GeCompletedtoGeExtended($u, $t);
				$this->geSub($t, $u, $Ai[(-$aslide[$i])/2]);
			}

			if ($bslide[$i] > 0) {
				$this->GeCompletedtoGeExtended($u, $t);
				$this->geMixedAdd($t, $u, static::$Bi[$bslide[$i]/2]);
			} else if ($bslide[$i] < 0) {
				$this->GeCompletedtoGeExtended($u, $t);
				$this->geMixedSub($t, $u, static::$Bi[(-$bslide[$i])/2]);
			}

			$this->GeCompletedtoGeProjective($r, $t);
		}
	}

	function scReduce($s) {
		$s0 = 2097151 & $this->feLoad3($s, 0);
		$s1 = 2097151 & ($this->feLoad4($s, 2) >> 5);
		$s2 = 2097151 & ($this->feLoad3($s, 5) >> 2);
		$s3 = 2097151 & ($this->feLoad4($s, 7) >> 7);
		$s4 = 2097151 & ($this->feLoad4($s, 10) >> 4);
		$s5 = 2097151 & ($this->feLoad3($s, 13) >> 1);
		$s6 = 2097151 & ($this->feLoad4($s, 15) >> 6);
		$s7 = 2097151 & ($this->feLoad3($s, 18) >> 3);
		$s8 = 2097151 & $this->feLoad3($s, 21);
		$s9 = 2097151 & ($this->feLoad4($s, 23) >> 5);
		$s10 = 2097151 & ($this->feLoad3($s, 26) >> 2);
		$s11 = 2097151 & ($this->feLoad4($s, 28) >> 7);
		$s12 = 2097151 & ($this->feLoad4($s, 31) >> 4);
		$s13 = 2097151 & ($this->feLoad3($s, 34) >> 1);
		$s14 = 2097151 & ($this->feLoad4($s, 36) >> 6);
		$s15 = 2097151 & ($this->feLoad3($s, 39) >> 3);
		$s16 = 2097151 & $this->feLoad3($s, 42);
		$s17 = 2097151 & ($this->feLoad4($s, 44) >> 5);
		$s18 = 2097151 & ($this->feLoad3($s, 47) >> 2);
		$s19 = 2097151 & ($this->feLoad4($s, 49) >> 7);
		$s20 = 2097151 & ($this->feLoad4($s, 52) >> 4);
		$s21 = 2097151 & ($this->feLoad3($s, 55) >> 1);
		$s22 = 2097151 & ($this->feLoad4($s, 57) >> 6);
		$s23 = ($this->feLoad4($s, 60) >> 3);

		$s11 += $s23 * 666643;
		$s12 += $s23 * 470296;
		$s13 += $s23 * 654183;
		$s14 -= $s23 * 997805;
		$s15 += $s23 * 136657;
		$s16 -= $s23 * 683901;
		$s23 = 0;

		$s10 += $s22 * 666643;
		$s11 += $s22 * 470296;
		$s12 += $s22 * 654183;
		$s13 -= $s22 * 997805;
		$s14 += $s22 * 136657;
		$s15 -= $s22 * 683901;
		$s22 = 0;

		$s9 += $s21 * 666643;
		$s10 += $s21 * 470296;
		$s11 += $s21 * 654183;
		$s12 -= $s21 * 997805;
		$s13 += $s21 * 136657;
		$s14 -= $s21 * 683901;
		$s21 = 0;

		$s8 += $s20 * 666643;
		$s9 += $s20 * 470296;
		$s10 += $s20 * 654183;
		$s11 -= $s20 * 997805;
		$s12 += $s20 * 136657;
		$s13 -= $s20 * 683901;
		$s20 = 0;

		$s7 += $s19 * 666643;
		$s8 += $s19 * 470296;
		$s9 += $s19 * 654183;
		$s10 -= $s19 * 997805;
		$s11 += $s19 * 136657;
		$s12 -= $s19 * 683901;
		$s19 = 0;

		$s6 += $s18 * 666643;
		$s7 += $s18 * 470296;
		$s8 += $s18 * 654183;
		$s9 -= $s18 * 997805;
		$s10 += $s18 * 136657;
		$s11 -= $s18 * 683901;
		$s18 = 0;

		$carry6 = ($s6 + (1<<20)) >> 21; $s7 += $carry6; $s6 -= $carry6 << 21;
		$carry8 = ($s8 + (1<<20)) >> 21; $s9 += $carry8; $s8 -= $carry8 << 21;
		$carry10 = ($s10 + (1<<20)) >> 21; $s11 += $carry10; $s10 -= $carry10 << 21;
		$carry12 = ($s12 + (1<<20)) >> 21; $s13 += $carry12; $s12 -= $carry12 << 21;
		$carry14 = ($s14 + (1<<20)) >> 21; $s15 += $carry14; $s14 -= $carry14 << 21;
		$carry16 = ($s16 + (1<<20)) >> 21; $s17 += $carry16; $s16 -= $carry16 << 21;

		$carry7 = ($s7 + (1<<20)) >> 21; $s8 += $carry7; $s7 -= $carry7 << 21;
		$carry9 = ($s9 + (1<<20)) >> 21; $s10 += $carry9; $s9 -= $carry9 << 21;
		$carry11 = ($s11 + (1<<20)) >> 21; $s12 += $carry11; $s11 -= $carry11 << 21;
		$carry13 = ($s13 + (1<<20)) >> 21; $s14 += $carry13; $s13 -= $carry13 << 21;
		$carry15 = ($s15 + (1<<20)) >> 21; $s16 += $carry15; $s15 -= $carry15 << 21;

		$s5 += $s17 * 666643;
		$s6 += $s17 * 470296;
		$s7 += $s17 * 654183;
		$s8 -= $s17 * 997805;
		$s9 += $s17 * 136657;
		$s10 -= $s17 * 683901;
		$s17 = 0;

		$s4 += $s16 * 666643;
		$s5 += $s16 * 470296;
		$s6 += $s16 * 654183;
		$s7 -= $s16 * 997805;
		$s8 += $s16 * 136657;
		$s9 -= $s16 * 683901;
		$s16 = 0;

		$s3 += $s15 * 666643;
		$s4 += $s15 * 470296;
		$s5 += $s15 * 654183;
		$s6 -= $s15 * 997805;
		$s7 += $s15 * 136657;
		$s8 -= $s15 * 683901;
		$s15 = 0;

		$s2 += $s14 * 666643;
		$s3 += $s14 * 470296;
		$s4 += $s14 * 654183;
		$s5 -= $s14 * 997805;
		$s6 += $s14 * 136657;
		$s7 -= $s14 * 683901;
		$s14 = 0;

		$s1 += $s13 * 666643;
		$s2 += $s13 * 470296;
		$s3 += $s13 * 654183;
		$s4 -= $s13 * 997805;
		$s5 += $s13 * 136657;
		$s6 -= $s13 * 683901;
		$s13 = 0;

		$s0 += $s12 * 666643;
		$s1 += $s12 * 470296;
		$s2 += $s12 * 654183;
		$s3 -= $s12 * 997805;
		$s4 += $s12 * 136657;
		$s5 -= $s12 * 683901;
		$s12 = 0;

		$carry0 = ($s0 + (1<<20)) >> 21; $s1 += $carry0; $s0 -= $carry0 << 21;
		$carry2 = ($s2 + (1<<20)) >> 21; $s3 += $carry2; $s2 -= $carry2 << 21;
		$carry4 = ($s4 + (1<<20)) >> 21; $s5 += $carry4; $s4 -= $carry4 << 21;
		$carry6 = ($s6 + (1<<20)) >> 21; $s7 += $carry6; $s6 -= $carry6 << 21;
		$carry8 = ($s8 + (1<<20)) >> 21; $s9 += $carry8; $s8 -= $carry8 << 21;
		$carry10 = ($s10 + (1<<20)) >> 21; $s11 += $carry10; $s10 -= $carry10 << 21;

		$carry1 = ($s1 + (1<<20)) >> 21; $s2 += $carry1; $s1 -= $carry1 << 21;
		$carry3 = ($s3 + (1<<20)) >> 21; $s4 += $carry3; $s3 -= $carry3 << 21;
		$carry5 = ($s5 + (1<<20)) >> 21; $s6 += $carry5; $s5 -= $carry5 << 21;
		$carry7 = ($s7 + (1<<20)) >> 21; $s8 += $carry7; $s7 -= $carry7 << 21;
		$carry9 = ($s9 + (1<<20)) >> 21; $s10 += $carry9; $s9 -= $carry9 << 21;
		$carry11 = ($s11 + (1<<20)) >> 21; $s12 += $carry11; $s11 -= $carry11 << 21;

		$s0 += $s12 * 666643;
		$s1 += $s12 * 470296;
		$s2 += $s12 * 654183;
		$s3 -= $s12 * 997805;
		$s4 += $s12 * 136657;
		$s5 -= $s12 * 683901;
		$s12 = 0;

		$carry0 = $s0 >> 21; $s1 += $carry0; $s0 -= $carry0 << 21;
		$carry1 = $s1 >> 21; $s2 += $carry1; $s1 -= $carry1 << 21;
		$carry2 = $s2 >> 21; $s3 += $carry2; $s2 -= $carry2 << 21;
		$carry3 = $s3 >> 21; $s4 += $carry3; $s3 -= $carry3 << 21;
		$carry4 = $s4 >> 21; $s5 += $carry4; $s4 -= $carry4 << 21;
		$carry5 = $s5 >> 21; $s6 += $carry5; $s5 -= $carry5 << 21;
		$carry6 = $s6 >> 21; $s7 += $carry6; $s6 -= $carry6 << 21;
		$carry7 = $s7 >> 21; $s8 += $carry7; $s7 -= $carry7 << 21;
		$carry8 = $s8 >> 21; $s9 += $carry8; $s8 -= $carry8 << 21;
		$carry9 = $s9 >> 21; $s10 += $carry9; $s9 -= $carry9 << 21;
		$carry10 = $s10 >> 21; $s11 += $carry10; $s10 -= $carry10 << 21;
		$carry11 = $s11 >> 21; $s12 += $carry11; $s11 -= $carry11 << 21;

		$s0 += $s12 * 666643;
		$s1 += $s12 * 470296;
		$s2 += $s12 * 654183;
		$s3 -= $s12 * 997805;
		$s4 += $s12 * 136657;
		$s5 -= $s12 * 683901;
		$s12 = 0;

		$carry0 = $s0 >> 21; $s1 += $carry0; $s0 -= $carry0 << 21;
		$carry1 = $s1 >> 21; $s2 += $carry1; $s1 -= $carry1 << 21;
		$carry2 = $s2 >> 21; $s3 += $carry2; $s2 -= $carry2 << 21;
		$carry3 = $s3 >> 21; $s4 += $carry3; $s3 -= $carry3 << 21;
		$carry4 = $s4 >> 21; $s5 += $carry4; $s4 -= $carry4 << 21;
		$carry5 = $s5 >> 21; $s6 += $carry5; $s5 -= $carry5 << 21;
		$carry6 = $s6 >> 21; $s7 += $carry6; $s6 -= $carry6 << 21;
		$carry7 = $s7 >> 21; $s8 += $carry7; $s7 -= $carry7 << 21;
		$carry8 = $s8 >> 21; $s9 += $carry8; $s8 -= $carry8 << 21;
		$carry9 = $s9 >> 21; $s10 += $carry9; $s9 -= $carry9 << 21;
		$carry10 = $s10 >> 21; $s11 += $carry10; $s10 -= $carry10 << 21;

		$s[0] = ($s0 >> 0) & 0xff;
		$s[1] = ($s0 >> 8) & 0xff;
		$s[2] = (($s0 >> 16) | ($s1 << 5)) & 0xff;
		$s[3] = ($s1 >> 3) & 0xff;
		$s[4] = ($s1 >> 11) & 0xff;
		$s[5] = (($s1 >> 19) | ($s2 << 2)) & 0xff;
		$s[6] = ($s2 >> 6) & 0xff;
		$s[7] = (($s2 >> 14) | ($s3 << 7)) & 0xff;
		$s[8] = ($s3 >> 1) & 0xff;
		$s[9] = ($s3 >> 9) & 0xff;
		$s[10] = (($s3 >> 17) | ($s4 << 4)) & 0xff;
		$s[11] = ($s4 >> 4) & 0xff;
		$s[12] = ($s4 >> 12) & 0xff;
		$s[13] = (($s4 >> 20) | ($s5 << 1)) & 0xff;
		$s[14] = ($s5 >> 7) & 0xff;
		$s[15] = (($s5 >> 15) | ($s6 << 6)) & 0xff;
		$s[16] = ($s6 >> 2) & 0xff;
		$s[17] = ($s6 >> 10) & 0xff;
		$s[18] = (($s6 >> 18) | ($s7 << 3)) & 0xff;
		$s[19] = ($s7 >> 5) & 0xff;
		$s[20] = ($s7 >> 13) & 0xff;
		$s[21] = ($s8 >> 0) & 0xff;
		$s[22] = ($s8 >> 8) & 0xff;
		$s[23] = (($s8 >> 16) | ($s9 << 5)) & 0xff;
		$s[24] = ($s9 >> 3) & 0xff;
		$s[25] = ($s9 >> 11) & 0xff;
		$s[26] = (($s9 >> 19) | ($s10 << 2)) & 0xff;
		$s[27] = ($s10 >> 6) & 0xff;
		$s[28] = (($s10 >> 14) | ($s11 << 7)) & 0xff;
		$s[29] = ($s11 >> 1) & 0xff;
		$s[30] = ($s11 >> 9) & 0xff;
		$s[31] = ($s11 >> 17) & 0xff;
	}

	function scMulAdd($s, $a, $b, $c) {
		$a0 = 2097151 & $this->feLoad3($a, 0);
		$a1 = 2097151 & ($this->feLoad4($a, 2) >> 5);
		$a2 = 2097151 & ($this->feLoad3($a, 5) >> 2);
		$a3 = 2097151 & ($this->feLoad4($a, 7) >> 7);
		$a4 = 2097151 & ($this->feLoad4($a, 10) >> 4);
		$a5 = 2097151 & ($this->feLoad3($a, 13) >> 1);
		$a6 = 2097151 & ($this->feLoad4($a, 15) >> 6);
		$a7 = 2097151 & ($this->feLoad3($a, 18) >> 3);
		$a8 = 2097151 & $this->feLoad3($a, 21);
		$a9 = 2097151 & ($this->feLoad4($a, 23) >> 5);
		$a10 = 2097151 & ($this->feLoad3($a, 26) >> 2);
		$a11 = ($this->feLoad4($a, 28) >> 7);
		$b0 = 2097151 & $this->feLoad3($b, 0);
		$b1 = 2097151 & ($this->feLoad4($b, 2) >> 5);
		$b2 = 2097151 & ($this->feLoad3($b, 5) >> 2);
		$b3 = 2097151 & ($this->feLoad4($b, 7) >> 7);
		$b4 = 2097151 & ($this->feLoad4($b, 10) >> 4);
		$b5 = 2097151 & ($this->feLoad3($b, 13) >> 1);
		$b6 = 2097151 & ($this->feLoad4($b, 15) >> 6);
		$b7 = 2097151 & ($this->feLoad3($b, 18) >> 3);
		$b8 = 2097151 & $this->feLoad3($b, 21);
		$b9 = 2097151 & ($this->feLoad4($b, 23) >> 5);
		$b10 = 2097151 & ($this->feLoad3($b, 26) >> 2);
		$b11 = ($this->feLoad4($b, 28) >> 7);
		$c0 = 2097151 & $this->feLoad3($c, 0);
		$c1 = 2097151 & ($this->feLoad4($c, 2) >> 5);
		$c2 = 2097151 & ($this->feLoad3($c, 5) >> 2);
		$c3 = 2097151 & ($this->feLoad4($c, 7) >> 7);
		$c4 = 2097151 & ($this->feLoad4($c, 10) >> 4);
		$c5 = 2097151 & ($this->feLoad3($c, 13) >> 1);
		$c6 = 2097151 & ($this->feLoad4($c, 15) >> 6);
		$c7 = 2097151 & ($this->feLoad3($c, 18) >> 3);
		$c8 = 2097151 & $this->feLoad3($c, 21);
		$c9 = 2097151 & ($this->feLoad4($c, 23) >> 5);
		$c10 = 2097151 & ($this->feLoad3($c, 26) >> 2);
		$c11 = ($this->feLoad4($c, 28) >> 7);

		$s0 = $c0 + $a0*$b0;
		$s1 = $c1 + $a0*$b1 + $a1*$b0;
		$s2 = $c2 + $a0*$b2 + $a1*$b1 + $a2*$b0;
		$s3 = $c3 + $a0*$b3 + $a1*$b2 + $a2*$b1 + $a3*$b0;
		$s4 = $c4 + $a0*$b4 + $a1*$b3 + $a2*$b2 + $a3*$b1 + $a4*$b0;
		$s5 = $c5 + $a0*$b5 + $a1*$b4 + $a2*$b3 + $a3*$b2 + $a4*$b1 + $a5*$b0;
		$s6 = $c6 + $a0*$b6 + $a1*$b5 + $a2*$b4 + $a3*$b3 + $a4*$b2 + $a5*$b1 + $a6*$b0;
		$s7 = $c7 + $a0*$b7 + $a1*$b6 + $a2*$b5 + $a3*$b4 + $a4*$b3 + $a5*$b2 + $a6*$b1 + $a7*$b0;
		$s8 = $c8 + $a0*$b8 + $a1*$b7 + $a2*$b6 + $a3*$b5 + $a4*$b4 + $a5*$b3 + $a6*$b2 + $a7*$b1 + $a8*$b0;
		$s9 = $c9 + $a0*$b9 + $a1*$b8 + $a2*$b7 + $a3*$b6 + $a4*$b5 + $a5*$b4 + $a6*$b3 + $a7*$b2 + $a8*$b1 + $a9*$b0;
		$s10 = $c10 + $a0*$b10 + $a1*$b9 + $a2*$b8 + $a3*$b7 + $a4*$b6 + $a5*$b5 + $a6*$b4 + $a7*$b3 + $a8*$b2 + $a9*$b1 + $a10*$b0;
		$s11 = $c11 + $a0*$b11 + $a1*$b10 + $a2*$b9 + $a3*$b8 + $a4*$b7 + $a5*$b6 + $a6*$b5 + $a7*$b4 + $a8*$b3 + $a9*$b2 + $a10*$b1 + $a11*$b0;
		$s12 = $a1*$b11 + $a2*$b10 + $a3*$b9 + $a4*$b8 + $a5*$b7 + $a6*$b6 + $a7*$b5 + $a8*$b4 + $a9*$b3 + $a10*$b2 + $a11*$b1;
		$s13 = $a2*$b11 + $a3*$b10 + $a4*$b9 + $a5*$b8 + $a6*$b7 + $a7*$b6 + $a8*$b5 + $a9*$b4 + $a10*$b3 + $a11*$b2;
		$s14 = $a3*$b11 + $a4*$b10 + $a5*$b9 + $a6*$b8 + $a7*$b7 + $a8*$b6 + $a9*$b5 + $a10*$b4 + $a11*$b3;
		$s15 = $a4*$b11 + $a5*$b10 + $a6*$b9 + $a7*$b8 + $a8*$b7 + $a9*$b6 + $a10*$b5 + $a11*$b4;
		$s16 = $a5*$b11 + $a6*$b10 + $a7*$b9 + $a8*$b8 + $a9*$b7 + $a10*$b6 + $a11*$b5;
		$s17 = $a6*$b11 + $a7*$b10 + $a8*$b9 + $a9*$b8 + $a10*$b7 + $a11*$b6;
		$s18 = $a7*$b11 + $a8*$b10 + $a9*$b9 + $a10*$b8 + $a11*$b7;
		$s19 = $a8*$b11 + $a9*$b10 + $a10*$b9 + $a11*$b8;
		$s20 = $a9*$b11 + $a10*$b10 + $a11*$b9;
		$s21 = $a10*$b11 + $a11*$b10;
		$s22 = $a11*$b11;
		$s23 = 0;

		$carry0 = ($s0 + (1<<20)) >> 21; $s1 += $carry0; $s0 -= $carry0 << 21;
		$carry2 = ($s2 + (1<<20)) >> 21; $s3 += $carry2; $s2 -= $carry2 << 21;
		$carry4 = ($s4 + (1<<20)) >> 21; $s5 += $carry4; $s4 -= $carry4 << 21;
		$carry6 = ($s6 + (1<<20)) >> 21; $s7 += $carry6; $s6 -= $carry6 << 21;
		$carry8 = ($s8 + (1<<20)) >> 21; $s9 += $carry8; $s8 -= $carry8 << 21;
		$carry10 = ($s10 + (1<<20)) >> 21; $s11 += $carry10; $s10 -= $carry10 << 21;
		$carry12 = ($s12 + (1<<20)) >> 21; $s13 += $carry12; $s12 -= $carry12 << 21;
		$carry14 = ($s14 + (1<<20)) >> 21; $s15 += $carry14; $s14 -= $carry14 << 21;
		$carry16 = ($s16 + (1<<20)) >> 21; $s17 += $carry16; $s16 -= $carry16 << 21;
		$carry18 = ($s18 + (1<<20)) >> 21; $s19 += $carry18; $s18 -= $carry18 << 21;
		$carry20 = ($s20 + (1<<20)) >> 21; $s21 += $carry20; $s20 -= $carry20 << 21;
		$carry22 = ($s22 + (1<<20)) >> 21; $s23 += $carry22; $s22 -= $carry22 << 21;

		$carry1 = ($s1 + (1<<20)) >> 21; $s2 += $carry1; $s1 -= $carry1 << 21;
		$carry3 = ($s3 + (1<<20)) >> 21; $s4 += $carry3; $s3 -= $carry3 << 21;
		$carry5 = ($s5 + (1<<20)) >> 21; $s6 += $carry5; $s5 -= $carry5 << 21;
		$carry7 = ($s7 + (1<<20)) >> 21; $s8 += $carry7; $s7 -= $carry7 << 21;
		$carry9 = ($s9 + (1<<20)) >> 21; $s10 += $carry9; $s9 -= $carry9 << 21;
		$carry11 = ($s11 + (1<<20)) >> 21; $s12 += $carry11; $s11 -= $carry11 << 21;
		$carry13 = ($s13 + (1<<20)) >> 21; $s14 += $carry13; $s13 -= $carry13 << 21;
		$carry15 = ($s15 + (1<<20)) >> 21; $s16 += $carry15; $s15 -= $carry15 << 21;
		$carry17 = ($s17 + (1<<20)) >> 21; $s18 += $carry17; $s17 -= $carry17 << 21;
		$carry19 = ($s19 + (1<<20)) >> 21; $s20 += $carry19; $s19 -= $carry19 << 21;
		$carry21 = ($s21 + (1<<20)) >> 21; $s22 += $carry21; $s21 -= $carry21 << 21;

		$s11 += $s23 * 666643;
		$s12 += $s23 * 470296;
		$s13 += $s23 * 654183;
		$s14 -= $s23 * 997805;
		$s15 += $s23 * 136657;
		$s16 -= $s23 * 683901;
		$s23 = 0;

		$s10 += $s22 * 666643;
		$s11 += $s22 * 470296;
		$s12 += $s22 * 654183;
		$s13 -= $s22 * 997805;
		$s14 += $s22 * 136657;
		$s15 -= $s22 * 683901;
		$s22 = 0;

		$s9 += $s21 * 666643;
		$s10 += $s21 * 470296;
		$s11 += $s21 * 654183;
		$s12 -= $s21 * 997805;
		$s13 += $s21 * 136657;
		$s14 -= $s21 * 683901;
		$s21 = 0;

		$s8 += $s20 * 666643;
		$s9 += $s20 * 470296;
		$s10 += $s20 * 654183;
		$s11 -= $s20 * 997805;
		$s12 += $s20 * 136657;
		$s13 -= $s20 * 683901;
		$s20 = 0;

		$s7 += $s19 * 666643;
		$s8 += $s19 * 470296;
		$s9 += $s19 * 654183;
		$s10 -= $s19 * 997805;
		$s11 += $s19 * 136657;
		$s12 -= $s19 * 683901;
		$s19 = 0;

		$s6 += $s18 * 666643;
		$s7 += $s18 * 470296;
		$s8 += $s18 * 654183;
		$s9 -= $s18 * 997805;
		$s10 += $s18 * 136657;
		$s11 -= $s18 * 683901;
		$s18 = 0;

		$carry6 = ($s6 + (1<<20)) >> 21; $s7 += $carry6; $s6 -= $carry6 << 21;
		$carry8 = ($s8 + (1<<20)) >> 21; $s9 += $carry8; $s8 -= $carry8 << 21;
		$carry10 = ($s10 + (1<<20)) >> 21; $s11 += $carry10; $s10 -= $carry10 << 21;
		$carry12 = ($s12 + (1<<20)) >> 21; $s13 += $carry12; $s12 -= $carry12 << 21;
		$carry14 = ($s14 + (1<<20)) >> 21; $s15 += $carry14; $s14 -= $carry14 << 21;
		$carry16 = ($s16 + (1<<20)) >> 21; $s17 += $carry16; $s16 -= $carry16 << 21;

		$carry7 = ($s7 + (1<<20)) >> 21; $s8 += $carry7; $s7 -= $carry7 << 21;
		$carry9 = ($s9 + (1<<20)) >> 21; $s10 += $carry9; $s9 -= $carry9 << 21;
		$carry11 = ($s11 + (1<<20)) >> 21; $s12 += $carry11; $s11 -= $carry11 << 21;
		$carry13 = ($s13 + (1<<20)) >> 21; $s14 += $carry13; $s13 -= $carry13 << 21;
		$carry15 = ($s15 + (1<<20)) >> 21; $s16 += $carry15; $s15 -= $carry15 << 21;

		$s5 += $s17 * 666643;
		$s6 += $s17 * 470296;
		$s7 += $s17 * 654183;
		$s8 -= $s17 * 997805;
		$s9 += $s17 * 136657;
		$s10 -= $s17 * 683901;
		$s17 = 0;

		$s4 += $s16 * 666643;
		$s5 += $s16 * 470296;
		$s6 += $s16 * 654183;
		$s7 -= $s16 * 997805;
		$s8 += $s16 * 136657;
		$s9 -= $s16 * 683901;
		$s16 = 0;

		$s3 += $s15 * 666643;
		$s4 += $s15 * 470296;
		$s5 += $s15 * 654183;
		$s6 -= $s15 * 997805;
		$s7 += $s15 * 136657;
		$s8 -= $s15 * 683901;
		$s15 = 0;

		$s2 += $s14 * 666643;
		$s3 += $s14 * 470296;
		$s4 += $s14 * 654183;
		$s5 -= $s14 * 997805;
		$s6 += $s14 * 136657;
		$s7 -= $s14 * 683901;
		$s14 = 0;

		$s1 += $s13 * 666643;
		$s2 += $s13 * 470296;
		$s3 += $s13 * 654183;
		$s4 -= $s13 * 997805;
		$s5 += $s13 * 136657;
		$s6 -= $s13 * 683901;
		$s13 = 0;

		$s0 += $s12 * 666643;
		$s1 += $s12 * 470296;
		$s2 += $s12 * 654183;
		$s3 -= $s12 * 997805;
		$s4 += $s12 * 136657;
		$s5 -= $s12 * 683901;
		$s12 = 0;

		$carry0 = ($s0 + (1<<20)) >> 21; $s1 += $carry0; $s0 -= $carry0 << 21;
		$carry2 = ($s2 + (1<<20)) >> 21; $s3 += $carry2; $s2 -= $carry2 << 21;
		$carry4 = ($s4 + (1<<20)) >> 21; $s5 += $carry4; $s4 -= $carry4 << 21;
		$carry6 = ($s6 + (1<<20)) >> 21; $s7 += $carry6; $s6 -= $carry6 << 21;
		$carry8 = ($s8 + (1<<20)) >> 21; $s9 += $carry8; $s8 -= $carry8 << 21;
		$carry10 = ($s10 + (1<<20)) >> 21; $s11 += $carry10; $s10 -= $carry10 << 21;

		$carry1 = ($s1 + (1<<20)) >> 21; $s2 += $carry1; $s1 -= $carry1 << 21;
		$carry3 = ($s3 + (1<<20)) >> 21; $s4 += $carry3; $s3 -= $carry3 << 21;
		$carry5 = ($s5 + (1<<20)) >> 21; $s6 += $carry5; $s5 -= $carry5 << 21;
		$carry7 = ($s7 + (1<<20)) >> 21; $s8 += $carry7; $s7 -= $carry7 << 21;
		$carry9 = ($s9 + (1<<20)) >> 21; $s10 += $carry9; $s9 -= $carry9 << 21;
		$carry11 = ($s11 + (1<<20)) >> 21; $s12 += $carry11; $s11 -= $carry11 << 21;

		$s0 += $s12 * 666643;
		$s1 += $s12 * 470296;
		$s2 += $s12 * 654183;
		$s3 -= $s12 * 997805;
		$s4 += $s12 * 136657;
		$s5 -= $s12 * 683901;
		$s12 = 0;

		$carry0 = $s0 >> 21; $s1 += $carry0; $s0 -= $carry0 << 21;
		$carry1 = $s1 >> 21; $s2 += $carry1; $s1 -= $carry1 << 21;
		$carry2 = $s2 >> 21; $s3 += $carry2; $s2 -= $carry2 << 21;
		$carry3 = $s3 >> 21; $s4 += $carry3; $s3 -= $carry3 << 21;
		$carry4 = $s4 >> 21; $s5 += $carry4; $s4 -= $carry4 << 21;
		$carry5 = $s5 >> 21; $s6 += $carry5; $s5 -= $carry5 << 21;
		$carry6 = $s6 >> 21; $s7 += $carry6; $s6 -= $carry6 << 21;
		$carry7 = $s7 >> 21; $s8 += $carry7; $s7 -= $carry7 << 21;
		$carry8 = $s8 >> 21; $s9 += $carry8; $s8 -= $carry8 << 21;
		$carry9 = $s9 >> 21; $s10 += $carry9; $s9 -= $carry9 << 21;
		$carry10 = $s10 >> 21; $s11 += $carry10; $s10 -= $carry10 << 21;
		$carry11 = $s11 >> 21; $s12 += $carry11; $s11 -= $carry11 << 21;

		$s0 += $s12 * 666643;
		$s1 += $s12 * 470296;
		$s2 += $s12 * 654183;
		$s3 -= $s12 * 997805;
		$s4 += $s12 * 136657;
		$s5 -= $s12 * 683901;
		$s12 = 0;

		$carry0 = $s0 >> 21; $s1 += $carry0; $s0 -= $carry0 << 21;
		$carry1 = $s1 >> 21; $s2 += $carry1; $s1 -= $carry1 << 21;
		$carry2 = $s2 >> 21; $s3 += $carry2; $s2 -= $carry2 << 21;
		$carry3 = $s3 >> 21; $s4 += $carry3; $s3 -= $carry3 << 21;
		$carry4 = $s4 >> 21; $s5 += $carry4; $s4 -= $carry4 << 21;
		$carry5 = $s5 >> 21; $s6 += $carry5; $s5 -= $carry5 << 21;
		$carry6 = $s6 >> 21; $s7 += $carry6; $s6 -= $carry6 << 21;
		$carry7 = $s7 >> 21; $s8 += $carry7; $s7 -= $carry7 << 21;
		$carry8 = $s8 >> 21; $s9 += $carry8; $s8 -= $carry8 << 21;
		$carry9 = $s9 >> 21; $s10 += $carry9; $s9 -= $carry9 << 21;
		$carry10 = $s10 >> 21; $s11 += $carry10; $s10 -= $carry10 << 21;

		$s[0] = ($s0 >> 0) & 0xff;
		$s[1] = ($s0 >> 8) & 0xff;
		$s[2] = (($s0 >> 16) | ($s1 << 5)) & 0xff;
		$s[3] = ($s1 >> 3) & 0xff;
		$s[4] = ($s1 >> 11) & 0xff;
		$s[5] = (($s1 >> 19) | ($s2 << 2)) & 0xff;
		$s[6] = ($s2 >> 6) & 0xff;
		$s[7] = (($s2 >> 14) | ($s3 << 7)) & 0xff;
		$s[8] = ($s3 >> 1) & 0xff;
		$s[9] = ($s3 >> 9) & 0xff;
		$s[10] = (($s3 >> 17) | ($s4 << 4)) & 0xff;
		$s[11] = ($s4 >> 4) & 0xff;
		$s[12] = ($s4 >> 12) & 0xff;
		$s[13] = (($s4 >> 20) | ($s5 << 1)) & 0xff;
		$s[14] = ($s5 >> 7) & 0xff;
		$s[15] = (($s5 >> 15) | ($s6 << 6)) & 0xff;
		$s[16] = ($s6 >> 2) & 0xff;
		$s[17] = ($s6 >> 10) & 0xff;
		$s[18] = (($s6 >> 18) | ($s7 << 3)) & 0xff;
		$s[19] = ($s7 >> 5) & 0xff;
		$s[20] = ($s7 >> 13) & 0xff;
		$s[21] = ($s8 >> 0) & 0xff;
		$s[22] = ($s8 >> 8) & 0xff;
		$s[23] = (($s8 >> 16) | ($s9 << 5)) & 0xff;
		$s[24] = ($s9 >> 3) & 0xff;
		$s[25] = ($s9 >> 11) & 0xff;
		$s[26] = (($s9 >> 19) | ($s10 << 2)) & 0xff;
		$s[27] = ($s10 >> 6) & 0xff;
		$s[28] = (($s10 >> 14) | ($s11 << 7)) & 0xff;
		$s[29] = ($s11 >> 1) & 0xff;
		$s[30] = ($s11 >> 9) & 0xff;
		$s[31] = ($s11 >> 17) & 0xff;
	}

}
