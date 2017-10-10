<?php
/**
 * FieldElement
 *
 * 
 * SplFixedArray with more functions.
 *
 *
 * @author Devi Mandiri <devi.mandiri@gmail.com>
 * @link   https://github.com/devi/Salt
 *
 */
class FieldElement extends SplFixedArray {

	public function toString() {
		$this->rewind();
		$buf = "";
		while ($this->valid()) {
			$buf .= chr($this->current());
			$this->next();
		}
		$this->rewind();
		return $buf;
	}

	public function toHex() {
		$this->rewind();
		$hextable = "0123456789abcdef";
		$buf = "";
		while ($this->valid()) {
			$c = $this->current();
			$buf .= $hextable[$c>>4];
			$buf .= $hextable[$c&0x0f];
			$this->next();
		}
		$this->rewind();
		return $buf;
	}

	public function toBase64() {
		return base64_encode($this->toString());
	}

	public function toJson() {
		return json_encode($this->toString());
	}

	public function slice($offset, $length = null) {
		$length = $length ? $length : $this->getSize()-$offset;
		$slice = new FieldElement($length);
		for ($i = 0;$i < $length;++$i) {
			$slice[$i] = $this->offsetGet($i+$offset);
		}
		return $slice;
	}

	public function copy($src, $size, $offset = 0, $srcOffset = 0) {
		for ($i = 0;$i < $size;++$i) {
			$this->offsetSet($i+$offset, $src[$i+$srcOffset]);
		}
	}

	public static function fromArray($array, $save_indexes = true) {
		$l = count($array);
		$fe = new FieldElement($l);
		$array = $save_indexes ? $array : array_values($array);
		foreach ($array as $k => $v) $fe[$k] = $v;
		return $fe;
	}

	public static function fromString($str) {
		return static::fromArray(unpack("C*", $str), false);
	}

	public static function fromHex($hex) {
		$hex = preg_replace('/[^0-9a-f]/', '', $hex);
		return static::fromString(pack("H*", $hex));
	}

	public static function fromBase64($base64) {
		return FieldElement::fromString(base64_decode($base64, true));
	}

	public static function fromJson($json) {
		return FieldElement::fromArray(json_decode($json, true));
	}
}
