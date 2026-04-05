"use strict";
const crypto = require("crypto");

const DIGITS = "0123456789";
const ALPHANUMERIC = "0123456789abcdefghijklmnopqrstuvwxyz";

class FF3 {
  constructor(key, tweak, alphabet = ALPHANUMERIC) {
    if (![16, 24, 32].includes(key.length)) throw new Error("Key must be 16, 24, or 32 bytes");
    if (tweak.length !== 8) throw new Error("Tweak must be exactly 8 bytes");
    if (alphabet.length < 2) throw new Error("Alphabet must have >= 2 chars");
    // FF3 reverses the key
    this.key = Buffer.from([...key].reverse());
    this.tweak = tweak;
    this.alphabet = alphabet;
    this.radix = BigInt(alphabet.length);
    this.charMap = {};
    for (let i = 0; i < alphabet.length; i++) this.charMap[alphabet[i]] = i;
  }

  encrypt(plaintext) {
    const digits = this._toDigits(plaintext);
    return this._fromDigits(this._ff3Encrypt(digits));
  }

  decrypt(ciphertext) {
    const digits = this._toDigits(ciphertext);
    return this._fromDigits(this._ff3Decrypt(digits));
  }

  _toDigits(s) { return [...s].map(c => this.charMap[c]); }
  _fromDigits(d) { return d.map(i => this.alphabet[i]).join(""); }

  _aes(block) {
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

module.exports = { FF3, DIGITS, ALPHANUMERIC };
