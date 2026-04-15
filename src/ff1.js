"use strict";
const crypto = require("crypto");

const DIGITS = "0123456789";
const ALPHANUMERIC = "0123456789abcdefghijklmnopqrstuvwxyz";

class FF1 {
  constructor(key, tweak, alphabet = ALPHANUMERIC) {
    if (![16, 24, 32].includes(key.length)) throw new Error("Key must be 16, 24, or 32 bytes");
    if (alphabet.length < 2) throw new Error("Alphabet must have >= 2 chars");
    this.key = key;
    this.tweak = tweak;
    this.alphabet = alphabet;
    this.radix = BigInt(alphabet.length);
    this.charMap = {};
    for (let i = 0; i < alphabet.length; i++) this.charMap[alphabet[i]] = i;
  }

  encrypt(plaintext) {
    const digits = this._toDigits(plaintext);
    const result = this._ff1Encrypt(digits, this.tweak);
    return this._fromDigits(result);
  }

  decrypt(ciphertext) {
    const digits = this._toDigits(ciphertext);
    const result = this._ff1Decrypt(digits, this.tweak);
    return this._fromDigits(result);
  }

  _toDigits(s) { return [...s].map(c => this.charMap[c]); }
  _fromDigits(d) { return d.map(i => this.alphabet[i]).join(""); }

  _aes(block) {
    // NIST SP 800-38G requires AES-ECB as the PRF for FF1/FF3 Feistel rounds.
    // This is single-block encryption used as a building block, not ECB mode applied to user data.
    const cipher = crypto.createCipheriv(`aes-${this.key.length * 8}-ecb`, this.key, null);
    cipher.setAutoPadding(false);
    return Buffer.concat([cipher.update(block), cipher.final()]);
  }

  _prf(data) {
    let y = Buffer.alloc(16);
    for (let i = 0; i < data.length; i += 16) {
      const tmp = Buffer.alloc(16);
      for (let j = 0; j < 16; j++) tmp[j] = y[j] ^ data[i + j];
      y = this._aes(tmp);
    }
    return y;
  }

  _expandS(R, d) {
    const blocks = Math.ceil(d / 16);
    const out = Buffer.alloc(blocks * 16);
    R.copy(out, 0);
    for (let j = 1; j < blocks; j++) {
      const x = Buffer.alloc(16);
      x.writeBigUInt64BE(BigInt(j), 8);
      // XOR with R (not previous block) per NIST SP 800-38G
      for (let k = 0; k < 16; k++) x[k] ^= R[k];
      const enc = this._aes(x);
      enc.copy(out, j * 16);
    }
    return out.subarray(0, d);
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

  _computeB(v) {
    let pow = this.radix ** BigInt(v) - 1n;
    return Math.ceil(pow === 0n ? 1 : Number(pow.toString(2).length) / 8);
  }

  _buildP(u, n, t) {
    const P = Buffer.alloc(16);
    P[0] = 1; P[1] = 2; P[2] = 1;
    P[3] = Number(this.radix >> 16n) & 0xFF; P[4] = Number(this.radix >> 8n) & 0xFF; P[5] = Number(this.radix) & 0xFF;
    P[6] = 10; P[7] = u;
    P.writeUInt32BE(n, 8);
    P.writeUInt32BE(t, 12);
    return P;
  }

  _buildQ(T, i, numBytes, b) {
    const pad = (16 - ((T.length + 1 + b) % 16)) % 16;
    const Q = Buffer.alloc(T.length + pad + 1 + b);
    T.copy(Q, 0);
    Q[T.length + pad] = i;
    const start = Math.max(0, numBytes.length - b);
    const dest = Q.length - (numBytes.length - start);
    numBytes.copy(Q, dest, start);
    return Q;
  }

  _bigIntToBytes(x, b) {
    const hex = x.toString(16).padStart(b * 2, "0");
    return Buffer.from(hex.slice(-b * 2), "hex");
  }

  _ff1Encrypt(pt, T) {
    const n = pt.length, u = Math.floor(n / 2), v = n - u;
    let A = pt.slice(0, u), B = pt.slice(u);
    const b = this._computeB(v);
    const d = 4 * Math.ceil(b / 4) + 4;
    const P = this._buildP(u, n, T.length);

    for (let i = 0; i < 10; i++) {
      const numB = this._bigIntToBytes(this._num(B), b);
      const Q = this._buildQ(T, i, numB, b);
      const R = this._prf(Buffer.concat([P, Q]));
      const S = this._expandS(R, d);
      const y = BigInt("0x" + S.toString("hex"));
      const m = i % 2 === 0 ? u : v;
      const c = (this._num(A) + y) % (this.radix ** BigInt(m));
      [A, B] = [B, this._str(c, m)];
    }
    return [...A, ...B];
  }

  _ff1Decrypt(ct, T) {
    const n = ct.length, u = Math.floor(n / 2), v = n - u;
    let A = ct.slice(0, u), B = ct.slice(u);
    const b = this._computeB(v);
    const d = 4 * Math.ceil(b / 4) + 4;
    const P = this._buildP(u, n, T.length);

    for (let i = 9; i >= 0; i--) {
      const numA = this._bigIntToBytes(this._num(A), b);
      const Q = this._buildQ(T, i, numA, b);
      const R = this._prf(Buffer.concat([P, Q]));
      const S = this._expandS(R, d);
      const y = BigInt("0x" + S.toString("hex"));
      const m = i % 2 === 0 ? u : v;
      const mod = this.radix ** BigInt(m);
      let c = (this._num(B) - y) % mod;
      if (c < 0n) c += mod;
      [B, A] = [A, this._str(c, m)];
    }
    return [...A, ...B];
  }
}

module.exports = { FF1, DIGITS, ALPHANUMERIC };
