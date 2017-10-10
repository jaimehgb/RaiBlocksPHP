<?php
/**
 * Curve25519
 *
 *
 * Assembled from:
 *   https://github.com/floodyberry/curve25519-donna
 *
 * 
 * @link https://github.com/devi/Salt
 * 
 */
class Curve25519 {

	const KEYSIZE = 32;

	const MASK26 = 67108863;

	const MASK25 = 33554431;

	protected static $_instance;

	public static function instance() {
		if (!isset(static::$_instance)) {
			static::$_instance = new Curve25519();
		}
		return static::$_instance;
	}

	function feCopy($out, $in) {
		for ($i = 0; $i < 10; $i++) {
			$out[$i] = $in[$i];
		}
	}

	function add($out, $a, $b) {
		for ($i = 10; $i--;) {
			$out[$i] = $a[$i] + $b[$i];
		}
	}

	function sub($out, $a, $b) {
		$out[0] = 0x7ffffda + $a[0] - $b[0]     ; $c = ($out[0] >> 26); $out[0] &= static::MASK26;
		$out[1] = 0x3fffffe + $a[1] - $b[1] + $c; $c = ($out[1] >> 25); $out[1] &= static::MASK25;
		$out[2] = 0x7fffffe + $a[2] - $b[2] + $c; $c = ($out[2] >> 26); $out[2] &= static::MASK26;
		$out[3] = 0x3fffffe + $a[3] - $b[3] + $c; $c = ($out[3] >> 25); $out[3] &= static::MASK25;
		$out[4] = 0x7fffffe + $a[4] - $b[4] + $c; $c = ($out[4] >> 26); $out[4] &= static::MASK26;
		$out[5] = 0x3fffffe + $a[5] - $b[5] + $c; $c = ($out[5] >> 25); $out[5] &= static::MASK25;
		$out[6] = 0x7fffffe + $a[6] - $b[6] + $c; $c = ($out[6] >> 26); $out[6] &= static::MASK26;
		$out[7] = 0x3fffffe + $a[7] - $b[7] + $c; $c = ($out[7] >> 25); $out[7] &= static::MASK25;
		$out[8] = 0x7fffffe + $a[8] - $b[8] + $c; $c = ($out[8] >> 26); $out[8] &= static::MASK26;
		$out[9] = 0x3fffffe + $a[9] - $b[9] + $c; $c = ($out[9] >> 25); $out[9] &= static::MASK25;
		$out[0] += 19 * $c;
	}

	function scalar_product($out, $in, $scalar) {
		$a = ($in[0] * $scalar)     ; $out[0] = ($a & 0xffffffff) & static::MASK26; $c = ($a >> 26) & 0xffffffff;
		$a = ($in[1] * $scalar) + $c; $out[1] = ($a & 0xffffffff) & static::MASK25; $c = ($a >> 25) & 0xffffffff;
		$a = ($in[2] * $scalar) + $c; $out[2] = ($a & 0xffffffff) & static::MASK26; $c = ($a >> 26) & 0xffffffff;
		$a = ($in[3] * $scalar) + $c; $out[3] = ($a & 0xffffffff) & static::MASK25; $c = ($a >> 25) & 0xffffffff;
		$a = ($in[4] * $scalar) + $c; $out[4] = ($a & 0xffffffff) & static::MASK26; $c = ($a >> 26) & 0xffffffff;
		$a = ($in[5] * $scalar) + $c; $out[5] = ($a & 0xffffffff) & static::MASK25; $c = ($a >> 25) & 0xffffffff;
		$a = ($in[6] * $scalar) + $c; $out[6] = ($a & 0xffffffff) & static::MASK26; $c = ($a >> 26) & 0xffffffff;
		$a = ($in[7] * $scalar) + $c; $out[7] = ($a & 0xffffffff) & static::MASK25; $c = ($a >> 25) & 0xffffffff;
		$a = ($in[8] * $scalar) + $c; $out[8] = ($a & 0xffffffff) & static::MASK26; $c = ($a >> 26) & 0xffffffff;
		$a = ($in[9] * $scalar) + $c; $out[9] = ($a & 0xffffffff) & static::MASK25; $c = ($a >> 25) & 0xffffffff;
		$out[0] += $c * 19;
	}

	function mul($out, $a, $b) {
		$r0 = $b[0];
		$r1 = $b[1];
		$r2 = $b[2];
		$r3 = $b[3];
		$r4 = $b[4];
		$r5 = $b[5];
		$r6 = $b[6];
		$r7 = $b[7];
		$r8 = $b[8];
		$r9 = $b[9];

		$s0 = $a[0];
		$s1 = $a[1];
		$s2 = $a[2];
		$s3 = $a[3];
		$s4 = $a[4];
		$s5 = $a[5];
		$s6 = $a[6];
		$s7 = $a[7];
		$s8 = $a[8];
		$s9 = $a[9];

		$m1 = ($r0 * $s1) + ($r1 * $s0);
		$m3 = ($r0 * $s3) + ($r1 * $s2) + ($r2 * $s1) + ($r3 * $s0);
		$m5 = ($r0 * $s5) + ($r1 * $s4) + ($r2 * $s3) + ($r3 * $s2) + ($r4 * $s1) + ($r5 * $s0);
		$m7 = ($r0 * $s7) + ($r1 * $s6) + ($r2 * $s5) + ($r3 * $s4) + ($r4 * $s3) + ($r5 * $s2) + ($r6 * $s1) + ($r7 * $s0);
		$m9 = ($r0 * $s9) + ($r1 * $s8) + ($r2 * $s7) + ($r3 * $s6) + ($r4 * $s5) + ($r5 * $s4) + ($r6 * $s3) + ($r7 * $s2) + ($r8 * $s1) + ($r9 * $s0);

		$r1 *= 2;
		$r3 *= 2;
		$r5 *= 2;
		$r7 *= 2;

		$m0 = ($r0 * $s0);
		$m2 = ($r0 * $s2) + ($r1 * $s1) + ($r2 * $s0);
		$m4 = ($r0 * $s4) + ($r1 * $s3) + ($r2 * $s2) + ($r3 * $s1) + ($r4 * $s0);
		$m6 = ($r0 * $s6) + ($r1 * $s5) + ($r2 * $s4) + ($r3 * $s3) + ($r4 * $s2) + ($r5 * $s1) + ($r6 * $s0);
		$m8 = ($r0 * $s8) + ($r1 * $s7) + ($r2 * $s6) + ($r3 * $s5) + ($r4 * $s4) + ($r5 * $s3) + ($r6 * $s2) + ($r7 * $s1) + ($r8 * $s0);

		$r1 *= 19;
		$r2 *= 19;
		$r3 = ($r3 / 2) * 19;
		$r4 *= 19;
		$r5 = ($r5 / 2) * 19;
		$r6 *= 19;
		$r7 = ($r7 / 2) * 19;
		$r8 *= 19;
		$r9 *= 19;

		$m1 += (($r9 * $s2) + ($r8 * $s3) + ($r7 * $s4) + ($r6 * $s5) + ($r5 * $s6) + ($r4 * $s7) + ($r3 * $s8) + ($r2 * $s9));
		$m3 += (($r9 * $s4) + ($r8 * $s5) + ($r7 * $s6) + ($r6 * $s7) + ($r5 * $s8) + ($r4 * $s9));
		$m5 += (($r9 * $s6) + ($r8 * $s7) + ($r7 * $s8) + ($r6 * $s9));
		$m7 += (($r9 * $s8) + ($r8 * $s9));

		$r3 *= 2;
		$r5 *= 2;
		$r7 *= 2;
		$r9 *= 2;

		$m0 += (($r9 * $s1) + ($r8 * $s2) + ($r7 * $s3) + ($r6 * $s4) + ($r5 * $s5) + ($r4 * $s6) + ($r3 * $s7) + ($r2 * $s8) + ($r1 * $s9));
		$m2 += (($r9 * $s3) + ($r8 * $s4) + ($r7 * $s5) + ($r6 * $s6) + ($r5 * $s7) + ($r4 * $s8) + ($r3 * $s9));
		$m4 += (($r9 * $s5) + ($r8 * $s6) + ($r7 * $s7) + ($r6 * $s8) + ($r5 * $s9));
		$m6 += (($r9 * $s7) + ($r8 * $s8) + ($r7 * $s9));
		$m8 += ($r9 * $s9);

		                       $r0 = ($m0 & 0xffffffff) & static::MASK26; $c = ($m0 >> 26);
		$m1 += $c;             $r1 = ($m1 & 0xffffffff) & static::MASK25; $c = ($m1 >> 25);
		$m2 += $c;             $r2 = ($m2 & 0xffffffff) & static::MASK26; $c = ($m2 >> 26);
		$m3 += $c;             $r3 = ($m3 & 0xffffffff) & static::MASK25; $c = ($m3 >> 25);
		$m4 += $c;             $r4 = ($m4 & 0xffffffff) & static::MASK26; $c = ($m4 >> 26);
		$m5 += $c;             $r5 = ($m5 & 0xffffffff) & static::MASK25; $c = ($m5 >> 25);
		$m6 += $c;             $r6 = ($m6 & 0xffffffff) & static::MASK26; $c = ($m6 >> 26);
		$m7 += $c;             $r7 = ($m7 & 0xffffffff) & static::MASK25; $c = ($m7 >> 25);
		$m8 += $c;             $r8 = ($m8 & 0xffffffff) & static::MASK26; $c = ($m8 >> 26);
		$m9 += $c;             $r9 = ($m9 & 0xffffffff) & static::MASK25; $p = ($m9 >> 25) & 0xffffffff;
		$m0 = $r0 + ($p * 19); $r0 = ($m0 & 0xffffffff) & static::MASK26; $p = ($m0 >> 26) & 0xffffffff;
		$r1 += $p;

		$out[0] = $r0;
		$out[1] = $r1;
		$out[2] = $r2;
		$out[3] = $r3;
		$out[4] = $r4;
		$out[5] = $r5;
		$out[6] = $r6;
		$out[7] = $r7;
		$out[8] = $r8;
		$out[9] = $r9;
	}

	function square($out, $in) {
		$r0 = $in[0];
		$r1 = $in[1];
		$r2 = $in[2];
		$r3 = $in[3];
		$r4 = $in[4];
		$r5 = $in[5];
		$r6 = $in[6];
		$r7 = $in[7];
		$r8 = $in[8];
		$r9 = $in[9];


		$m0 = ($r0 * $r0);
		$r0 *= 2;
		$m1 = ($r0 * $r1);
		$m2 = ($r0 * $r2) + ($r1 * $r1 * 2);
		$r1 *= 2;
		$m3 = ($r0 * $r3) + ($r1 * $r2    );
		$m4 = ($r0 * $r4) + ($r1 * $r3 * 2) + ($r2 * $r2);
		$r2 *= 2;
		$m5 = ($r0 * $r5) + ($r1 * $r4    ) + ($r2 * $r3);
		$m6 = ($r0 * $r6) + ($r1 * $r5 * 2) + ($r2 * $r4) + ($r3 * $r3 * 2);
		$r3 *= 2;
		$m7 = ($r0 * $r7) + ($r1 * $r6    ) + ($r2 * $r5) + ($r3 * $r4    );
		$m8 = ($r0 * $r8) + ($r1 * $r7 * 2) + ($r2 * $r6) + ($r3 * $r5 * 2) + ($r4 * $r4    );
		$m9 = ($r0 * $r9) + ($r1 * $r8    ) + ($r2 * $r7) + ($r3 * $r6    ) + ($r4 * $r5 * 2);

		$d6 = $r6 * 19;
		$d7 = $r7 * 2 * 19;
		$d8 = $r8 * 19;
		$d9 = $r9 * 2 * 19;

		$m0 += (($d9 * $r1    ) + ($d8 * $r2    ) + ($d7 * $r3    ) + ($d6 * $r4 * 2) + ($r5 * $r5 * 2 * 19));
		$m1 += (($d9 * $r2 / 2) + ($d8 * $r3    ) + ($d7 * $r4    ) + ($d6 * $r5 * 2));
		$m2 += (($d9 * $r3    ) + ($d8 * $r4 * 2) + ($d7 * $r5 * 2) + ($d6 * $r6    ));
		$m3 += (($d9 * $r4    ) + ($d8 * $r5 * 2) + ($d7 * $r6    ));
		$m4 += (($d9 * $r5 * 2) + ($d8 * $r6 * 2) + ($d7 * $r7    ));
		$m5 += (($d9 * $r6    ) + ($d8 * $r7 * 2));
		$m6 += (($d9 * $r7 * 2) + ($d8 * $r8    ));
		$m7 += ( $d9 * $r8    );
		$m8 += ( $d9 * $r9    );

		                     $r0 = ($m0 & 0xffffffff) & static::MASK26; $c = ($m0 >> 26);
		$m1 += $c;           $r1 = ($m1 & 0xffffffff) & static::MASK25; $c = ($m1 >> 25);
		$m2 += $c;           $r2 = ($m2 & 0xffffffff) & static::MASK26; $c = ($m2 >> 26);
		$m3 += $c;           $r3 = ($m3 & 0xffffffff) & static::MASK25; $c = ($m3 >> 25);
		$m4 += $c;           $r4 = ($m4 & 0xffffffff) & static::MASK26; $c = ($m4 >> 26);
		$m5 += $c;           $r5 = ($m5 & 0xffffffff) & static::MASK25; $c = ($m5 >> 25);
		$m6 += $c;           $r6 = ($m6 & 0xffffffff) & static::MASK26; $c = ($m6 >> 26);
		$m7 += $c;           $r7 = ($m7 & 0xffffffff) & static::MASK25; $c = ($m7 >> 25);
		$m8 += $c;           $r8 = ($m8 & 0xffffffff) & static::MASK26; $c = ($m8 >> 26);
		$m9 += $c;           $r9 = ($m9 & 0xffffffff) & static::MASK25; $p = ($m9 >> 25) & 0xffffffff;
		$m0 = $r0 + ($p*19); $r0 = ($m0 & 0xffffffff) & static::MASK26; $p = ($m0 >> 26) & 0xffffffff;
		$r1 += $p;

		$out[0] = $r0;
		$out[1] = $r1;
		$out[2] = $r2;
		$out[3] = $r3;
		$out[4] = $r4;
		$out[5] = $r5;
		$out[6] = $r6;
		$out[7] = $r7;
		$out[8] = $r8;
		$out[9] = $r9;
	}

	function square_times($out, $in, $count) {
		$r0 = $in[0];
		$r1 = $in[1];
		$r2 = $in[2];
		$r3 = $in[3];
		$r4 = $in[4];
		$r5 = $in[5];
		$r6 = $in[6];
		$r7 = $in[7];
		$r8 = $in[8];
		$r9 = $in[9];

		do {
			$m0 = ($r0 * $r0);
			$r0 *= 2;
			$m1 = ($r0 * $r1);
			$m2 = ($r0 * $r2) + ($r1 * $r1 * 2);
			$r1 *= 2;
			$m3 = ($r0 * $r3) + ($r1 * $r2    );
			$m4 = ($r0 * $r4) + ($r1 * $r3 * 2) + ($r2 * $r2);
			$r2 *= 2;
			$m5 = ($r0 * $r5) + ($r1 * $r4    ) + ($r2 * $r3);
			$m6 = ($r0 * $r6) + ($r1 * $r5 * 2) + ($r2 * $r4) + ($r3 * $r3 * 2);
			$r3 *= 2;
			$m7 = ($r0 * $r7) + ($r1 * $r6    ) + ($r2 * $r5) + ($r3 * $r4    );
			$m8 = ($r0 * $r8) + ($r1 * $r7 * 2) + ($r2 * $r6) + ($r3 * $r5 * 2) + ($r4 * $r4    );
			$m9 = ($r0 * $r9) + ($r1 * $r8    ) + ($r2 * $r7) + ($r3 * $r6    ) + ($r4 * $r5 * 2);

			$d6 = $r6 * 19;
			$d7 = $r7 * 2 * 19;
			$d8 = $r8 * 19;
			$d9 = $r9 * 2 * 19;

			$m0 += (($d9 * $r1    ) + ($d8 * $r2    ) + ($d7 * $r3    ) + ($d6 * $r4 * 2) + ($r5 * $r5 * 2 * 19));
			$m1 += (($d9 * $r2 / 2) + ($d8 * $r3    ) + ($d7 * $r4    ) + ($d6 * $r5 * 2));
			$m2 += (($d9 * $r3    ) + ($d8 * $r4 * 2) + ($d7 * $r5 * 2) + ($d6 * $r6    ));
			$m3 += (($d9 * $r4    ) + ($d8 * $r5 * 2) + ($d7 * $r6    ));
			$m4 += (($d9 * $r5 * 2) + ($d8 * $r6 * 2) + ($d7 * $r7    ));
			$m5 += (($d9 * $r6    ) + ($d8 * $r7 * 2));
			$m6 += (($d9 * $r7 * 2) + ($d8 * $r8    ));
			$m7 += ( $d9 * $r8    );
			$m8 += ( $d9 * $r9    );

			                     $r0 = ($m0 & 0xffffffff) & static::MASK26; $c = ($m0 >> 26);
			$m1 += $c;           $r1 = ($m1 & 0xffffffff) & static::MASK25; $c = ($m1 >> 25);
			$m2 += $c;           $r2 = ($m2 & 0xffffffff) & static::MASK26; $c = ($m2 >> 26);
			$m3 += $c;           $r3 = ($m3 & 0xffffffff) & static::MASK25; $c = ($m3 >> 25);
			$m4 += $c;           $r4 = ($m4 & 0xffffffff) & static::MASK26; $c = ($m4 >> 26);
			$m5 += $c;           $r5 = ($m5 & 0xffffffff) & static::MASK25; $c = ($m5 >> 25);
			$m6 += $c;           $r6 = ($m6 & 0xffffffff) & static::MASK26; $c = ($m6 >> 26);
			$m7 += $c;           $r7 = ($m7 & 0xffffffff) & static::MASK25; $c = ($m7 >> 25);
			$m8 += $c;           $r8 = ($m8 & 0xffffffff) & static::MASK26; $c = ($m8 >> 26);
			$m9 += $c;           $r9 = ($m9 & 0xffffffff) & static::MASK25; $p = ($m9 >> 25) & 0xffffffff;
			$m0 = $r0 + ($p*19); $r0 = ($m0 & 0xffffffff) & static::MASK26; $p = ($m0 >> 26) & 0xffffffff;
			$r1 += $p;
		} while (--$count);

		$out[0] = $r0;
		$out[1] = $r1;
		$out[2] = $r2;
		$out[3] = $r3;
		$out[4] = $r4;
		$out[5] = $r5;
		$out[6] = $r6;
		$out[7] = $r7;
		$out[8] = $r8;
		$out[9] = $r9;
	}

	function load32($in, $pos) {
		return $in[$pos] | ($in[$pos+1]<<8) | ($in[$pos+2]<<16) | ($in[$pos+3]<<24);
	}

	function expand($out, $in) {
		$x0 = $this->load32($in,  0);
		$x1 = $this->load32($in,  4);
		$x2 = $this->load32($in,  8);
		$x3 = $this->load32($in, 12);
		$x4 = $this->load32($in, 16);
		$x5 = $this->load32($in, 20);
		$x6 = $this->load32($in, 24);
		$x7 = $this->load32($in, 28);

		$out[0] = (               $x0       ) & static::MASK26;
		$out[1] = ((($x1 << 32) | $x0) >> 26) & static::MASK25;
		$out[2] = ((($x2 << 32) | $x1) >> 19) & static::MASK26;
		$out[3] = ((($x3 << 32) | $x2) >> 13) & static::MASK25;
		$out[4] = ((              $x3) >>  6) & static::MASK26;
		$out[5] = (               $x4       ) & static::MASK25;
		$out[6] = ((($x5 << 32) | $x4) >> 25) & static::MASK26;
		$out[7] = ((($x6 << 32) | $x5) >> 19) & static::MASK25;
		$out[8] = ((($x7 << 32) | $x6) >> 12) & static::MASK26;
		$out[9] = ((              $x7) >>  6) & static::MASK25;
	}

	function carry_pass($f) {
		$f[1] += $f[0] >> 26; $f[0] &= static::MASK26;
		$f[2] += $f[1] >> 25; $f[1] &= static::MASK25;
		$f[3] += $f[2] >> 26; $f[2] &= static::MASK26;
		$f[4] += $f[3] >> 25; $f[3] &= static::MASK25;
		$f[5] += $f[4] >> 26; $f[4] &= static::MASK26;
		$f[6] += $f[5] >> 25; $f[5] &= static::MASK25;
		$f[7] += $f[6] >> 26; $f[6] &= static::MASK26;
		$f[8] += $f[7] >> 25; $f[7] &= static::MASK25;
		$f[9] += $f[8] >> 26; $f[8] &= static::MASK26;
	}

	function carry_pass_full($f) {
		$this->carry_pass($f);
		$f[0] += 19 * ($f[9] >> 25);
		$f[9] &= static::MASK25;
	}

	function carry_pass_final($f) {
		$this->carry_pass($f);
		$f[9] &= static::MASK25;
	}

	function store32($out, $pos, $in) {
		$out[$pos]  |= $in & 0xff; $in >>= 8;
		$out[$pos+1] = $in & 0xff; $in >>= 8;
		$out[$pos+2] = $in & 0xff; $in >>= 8;
		$out[$pos+3] = $in & 0xff;
	}

	function contract($out, $in) {
		$f = new SplFixedArray(10);

		$this->feCopy($f, $in);
		$this->carry_pass_full($f);
		$this->carry_pass_full($f);

		$f[0] += 19;
		$this->carry_pass_full($f);

		$f[0] += (1 << 26) - 19;
		$f[1] += static::MASK25;
		$f[2] += static::MASK26;
		$f[3] += static::MASK25;
		$f[4] += static::MASK26;
		$f[5] += static::MASK25;
		$f[6] += static::MASK26;
		$f[7] += static::MASK25;
		$f[8] += static::MASK26;
		$f[9] += static::MASK25;

		$this->carry_pass_final($f);

		$f[1] <<= 2;
		$f[2] <<= 3;
		$f[3] <<= 5;
		$f[4] <<= 6;
		$f[6] <<= 1;
		$f[7] <<= 3;
		$f[8] <<= 4;
		$f[9] <<= 6;

		$out[0] = 0;
		$out[16] = 0;

		$this->store32($out,  0, $f[0]); 
		$this->store32($out,  3, $f[1]);
		$this->store32($out,  6, $f[2]);
		$this->store32($out,  9, $f[3]);
		$this->store32($out, 12, $f[4]);
		$this->store32($out, 16, $f[5]);
		$this->store32($out, 19, $f[6]);
		$this->store32($out, 22, $f[7]);
		$this->store32($out, 25, $f[8]);
		$this->store32($out, 28, $f[9]);
	}

	function swap_conditional($x, $qpx, $iswap) {
		$swap = -$iswap;

		for ($i = 0; $i < 10; $i++) {
			$t = $swap & ($x[$i] ^ $qpx[$i]);
			$x[$i]   ^= $t;
			$qpx[$i] ^= $t;
		}
	}

	function pow_two5mtwo0_two250mtwo0($b) {
		$c = new SplFixedArray(16);
		$t0 = new SplFixedArray(16);

		$this->square_times($t0, $b, 5);
		$this->mul($b, $t0, $b);
		$this->square_times($t0, $b, 10);
		$this->mul($c, $t0, $b);
		$this->square_times($t0, $c, 20);
		$this->mul($t0, $t0, $c);
		$this->square_times($t0, $t0, 10);
		$this->mul($b, $t0, $b);
		$this->square_times($t0, $b, 50);
		$this->mul($c, $t0, $b);
		$this->square_times($t0, $c, 100);
		$this->mul($t0, $t0, $c);
		$this->square_times($t0, $t0, 50);
		$this->mul($b, $t0, $b);
	}

	function recip($out, $z) {
		$a = new SplFixedArray(16);
		$b = new SplFixedArray(16);
		$t0 = new SplFixedArray(16);

		$this->square($a, $z);
		$this->square_times($t0, $a, 2);
		$this->mul($b, $t0, $z);
		$this->mul($a, $b, $a);
		$this->square($t0, $a);
		$this->mul($b, $t0, $b);
		$this->pow_two5mtwo0_two250mtwo0($b);
		$this->square_times($b, $b, 5);
		$this->mul($out, $b, $a);
	}

	function scalarmult($secret, $basepoint) {
		$nqpqx = new SplFixedArray(10); $nqpqx[0] = 1;
		$nqpqz = new SplFixedArray(10);
		$nqz = new SplFixedArray(10); $nqz[0] = 1;
		$nqx = new SplFixedArray(10);
		$q = new SplFixedArray(10);
		$qx = new SplFixedArray(10);
		$qpqx = new SplFixedArray(10);
		$qqx = new SplFixedArray(10);
		$zzz = new SplFixedArray(10);
		$zmone = new SplFixedArray(10);
		$e = new SplFixedArray(32);
		$pk = new SplFixedArray(32);

		for ($i = 32; $i--;) $e[$i] = $secret[$i];
		$e[0] &= 0xf8;
		$e[31] &= 0x7f;
		$e[31] |= 0x40;

		$this->expand($q, $basepoint);
		$this->feCopy($nqx, $q);

		/* $bit 255 is always 0, and $bit 254 is always 1, so skip $bit 255 and 
		   start pre-swapped on $bit 254 */
		$lastbit = 1;

		/* we are doing $bits 254..3 in the loop, but are swapping in $bits 253..2 */
		for ($i = 253; $i >= 2; $i--) {
			$this->add($qx, $nqx, $nqz);
			$this->sub($nqz, $nqx, $nqz);
			$this->add($qpqx, $nqpqx, $nqpqz);
			$this->sub($nqpqz, $nqpqx, $nqpqz);
			$this->mul($nqpqx, $qpqx, $nqz);
			$this->mul($nqpqz, $qx, $nqpqz);
			$this->add($qqx, $nqpqx, $nqpqz);
			$this->sub($nqpqz, $nqpqx, $nqpqz);
			$this->square($nqpqz, $nqpqz);
			$this->square($nqpqx, $qqx);
			$this->mul($nqpqz, $nqpqz, $q);
			$this->square($qx, $qx);
			$this->square($nqz, $nqz);
			$this->mul($nqx, $qx, $nqz);
			$this->sub($nqz, $qx, $nqz);
			$this->scalar_product($zzz, $nqz, 121665);
			$this->add($zzz, $zzz, $qx);
			$this->mul($nqz, $nqz, $zzz);

			$bit = ($e[$i/8] >> ($i & 7)) & 1;
			$this->swap_conditional($nqx, $nqpqx, $bit ^ $lastbit);
			$this->swap_conditional($nqz, $nqpqz, $bit ^ $lastbit);
			$lastbit = $bit;
		}

		/* the final 3 $bits are always zero, so we only need to double */
		for ($i = 0; $i < 3; $i++) {
			$this->add($qx, $nqx, $nqz);
			$this->sub($nqz, $nqx, $nqz);
			$this->square($qx, $qx);
			$this->square($nqz, $nqz);
			$this->mul($nqx, $qx, $nqz);
			$this->sub($nqz, $qx, $nqz);
			$this->scalar_product($zzz, $nqz, 121665);
			$this->add($zzz, $zzz, $qx);
			$this->mul($nqz, $nqz, $zzz);
		}

		$this->recip($zmone, $nqz);
		$this->mul($nqz, $nqx, $zmone);
		$this->contract($pk, $nqz);
		return $pk;
	}


	function scalarbase($secret) {
		$basepoint = new SplFixedArray(32);
		$basepoint[0] = 9;
		return $this->scalarmult($secret, $basepoint);
	}

}
