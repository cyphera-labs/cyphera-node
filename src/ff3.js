"use strict";
const crypto = require("crypto");

const DIGITS = "0123456789";
const ALPHANUMERIC = "0123456789abcdefghijklmnopqrstuvwxyz";

class FF3 {
  constructor(key, tweak, alphabet = ALPHANUMERIC) {
    if (![16, 24, 32].includes(key.length)) throw new Error(`invalid key length: ${key.length} (expected 16, 24, or 32)`);
    if (tweak.length !== 8) throw new Error(`invalid tweak length: ${tweak.length} (expected 8)`);
    if (alphabet.length < 2) throw new Error("Alphabet must have >= 2 chars");
    // FF3 reverses the key
    this.key = Buffer.from([...key].reverse());
    this.tweak = tweak;
    this.alphabet = alphabet;
    this.radix = BigInt(alphabet.length);
    this.charMap = {};
    for (let i = 0; i < alphabet.length; i++) this.charMap[alphabet[i]] = i;
    // NIST FF3 maximum length: 2 * floor(log_radix(2^96)), exact arithmetic.
    const limit = 1n << 96n;
    let k = 0n;
    while (this.radix ** (k + 1n) <= limit) k++;
    this.maxLen = 2 * Number(k);
  }

  // NIST SP 800-38G: length >= 2, radix^length >= 1,000,000, length <= maxLen.
  _checkLength(n) {
    if (n < 2 || this.radix ** BigInt(n) < 1000000n) {
      throw new Error("input too short (NIST minimum: length >= 2 and radix^length >= 1,000,000)");
    }
    if (n > this.maxLen) {
      throw new Error(`input too long (FF3 maximum for this radix is ${this.maxLen})`);
    }
  }

  encrypt(plaintext) {
    const digits = this._toDigits(plaintext);
    this._checkLength(digits.length);
    return this._fromDigits(this._ff3Encrypt(digits));
  }

  decrypt(ciphertext) {
    const digits = this._toDigits(ciphertext);
    this._checkLength(digits.length);
    return this._fromDigits(this._ff3Decrypt(digits));
  }

  _toDigits(s) {
    const arr = [...s];
    const out = new Array(arr.length);
    for (let i = 0; i < arr.length; i++) {
      const idx = this.charMap[arr[i]];
      if (idx === undefined) throw new Error(`invalid char '${arr[i]}' at position ${i}`);
      out[i] = idx;
    }
    return out;
  }
  _fromDigits(d) { return d.map(i => this.alphabet[i]).join(""); }

  _aes(block) {
    // NIST SP 800-38G requires AES-ECB as the PRF for FF1/FF3 Feistel rounds.
    // This is single-block encryption used as a building block, not ECB mode applied to user data.
    const cipher = crypto.createCipheriv(`aes-${this.key.length * 8}-ecb`, this.key, null);
    cipher.setAutoPadding(false);
    return Buffer.concat([cipher.update(block), cipher.final()]);
  }

  _num(digits) {
    let r = 0n;
    for (const d of digits) r = r * this.radix + BigInt(d);
    return r;
  }

  _str(num, len) {
    const r = new Array(len).fill(0);
    for (let i = len - 1; i >= 0; i--) { r[i] = Number(num % this.radix); num /= this.radix; }
    return r;
  }

  _calcP(round, w, half) {
    const input = Buffer.alloc(16);
    w.copy(input, 0);
    input[3] ^= round;

    const revHalf = [...half].reverse();
    const halfNum = this._num(revHalf);
    let hb;
    if (halfNum === 0n) {
      hb = Buffer.alloc(1);
    } else {
      const hex = halfNum.toString(16);
      hb = Buffer.from(hex.length % 2 ? "0" + hex : hex, "hex");
    }
    if (hb.length <= 12) {
      hb.copy(input, 16 - hb.length);
    } else {
      hb.copy(input, 4, hb.length - 12);
    }

    const revInput = Buffer.from([...input].reverse());
    const aesOut = this._aes(revInput);
    const revOut = Buffer.from([...aesOut].reverse());
    return BigInt("0x" + revOut.toString("hex"));
  }

  _ff3Encrypt(pt) {
    const n = pt.length, u = Math.ceil(n / 2), v = n - u;
    let A = pt.slice(0, u), B = pt.slice(u);

    for (let i = 0; i < 8; i++) {
      const w = i % 2 === 0 ? this.tweak.subarray(4, 8) : this.tweak.subarray(0, 4);
      if (i % 2 === 0) {
        const p = this._calcP(i, w, B);
        const m = this.radix ** BigInt(u);
        const aNum = this._num([...A].reverse());
        const y = (aNum + p) % m;
        A = this._str(y, u).reverse();
      } else {
        const p = this._calcP(i, w, A);
        const m = this.radix ** BigInt(v);
        const bNum = this._num([...B].reverse());
        const y = (bNum + p) % m;
        B = this._str(y, v).reverse();
      }
    }
    return [...A, ...B];
  }

  _ff3Decrypt(ct) {
    const n = ct.length, u = Math.ceil(n / 2), v = n - u;
    let A = ct.slice(0, u), B = ct.slice(u);

    for (let i = 7; i >= 0; i--) {
      const w = i % 2 === 0 ? this.tweak.subarray(4, 8) : this.tweak.subarray(0, 4);
      if (i % 2 === 0) {
        const p = this._calcP(i, w, B);
        const m = this.radix ** BigInt(u);
        const aNum = this._num([...A].reverse());
        let y = (aNum - p) % m;
        if (y < 0n) y += m;
        A = this._str(y, u).reverse();
      } else {
        const p = this._calcP(i, w, A);
        const m = this.radix ** BigInt(v);
        const bNum = this._num([...B].reverse());
        let y = (bNum - p) % m;
        if (y < 0n) y += m;
        B = this._str(y, v).reverse();
      }
    }
    return [...A, ...B];
  }
}

// expandFF31Tweak expands the 56-bit FF3-1 tweak into the 64-bit tweak the
// FF3 round function consumes (NIST SP 800-38G Rev 1): bytes[0:4] = T_L,
// bytes[4:8] = T_R.
function expandFF31Tweak(t) {
  return Buffer.from([
    t[0], t[1], t[2], t[3] & 0xf0,
    t[4], t[5], t[6], (t[3] & 0x0f) << 4,
  ]);
}

/**
 * FF3-1 Format-Preserving Encryption (NIST SP 800-38G Rev 1).
 *
 * FF3-1 is FF3 with a 56-bit (7-byte) tweak. The tweak is expanded into the
 * 64-bit form the FF3 round function consumes; the algorithm is identical FF3.
 */
class FF31 {
  constructor(key, tweak, alphabet = ALPHANUMERIC) {
    if (tweak.length !== 7) {
      throw new Error(`invalid tweak length: ${tweak.length} (expected 7)`);
    }
    this._ff3 = new FF3(key, expandFF31Tweak(tweak), alphabet);
  }

  encrypt(plaintext) { return this._ff3.encrypt(plaintext); }
  decrypt(ciphertext) { return this._ff3.decrypt(ciphertext); }
}

module.exports = { FF3, FF31, DIGITS, ALPHANUMERIC };
