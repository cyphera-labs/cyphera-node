"use strict";
const crypto = require("crypto");
const { FF1 } = require("./ff1");
const { FF3 } = require("./ff3");

const ALPHABETS = {
  digits: "0123456789",
  alpha_lower: "abcdefghijklmnopqrstuvwxyz",
  alpha_upper: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
  alpha: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
  alphanumeric: "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
};

function resolveAlphabet(name) {
  if (!name) return ALPHABETS.alphanumeric;
  return ALPHABETS[name] || name; // literal custom alphabet if not a known name
}

class Cyphera {
  constructor(config) {
    this._policies = {};
    this._tagIndex = {};
    this._keys = {};

    // Load keys
    const keys = config.keys || {};
    for (const [name, val] of Object.entries(keys)) {
      const material = typeof val === "string" ? val : val.material;
      this._keys[name] = Buffer.from(material, "hex");
    }

    // Load policies + build tag index
    const policies = config.policies || {};
    for (const [name, pol] of Object.entries(policies)) {
      const tagEnabled = pol.tag_enabled !== false; // default true
      const tag = pol.tag || null;

      if (tagEnabled && !tag) {
        throw new Error(`Policy '${name}' has tag_enabled=true but no tag specified`);
      }

      if (tagEnabled && tag) {
        if (this._tagIndex[tag]) {
          throw new Error(`Tag collision: '${tag}' used by both '${this._tagIndex[tag]}' and '${name}'`);
        }
        this._tagIndex[tag] = name;
      }

      this._policies[name] = {
        engine: pol.engine || "ff1",
        alphabet: resolveAlphabet(pol.alphabet),
        keyRef: pol.key_ref || null,
        tag,
        tagEnabled,
        tagLength: pol.tag_length || 3,
        pattern: pol.pattern || null,
        algorithm: pol.algorithm || "sha256",
      };
    }
  }

  protect(value, policyName) {
    const policy = this._getPolicy(policyName);

    switch (policy.engine) {
      case "ff1": return this._protectFpe(value, policy, false);
      case "ff3": return this._protectFpe(value, policy, true);
      case "mask": return this._protectMask(value, policy);
      case "hash": return this._protectHash(value, policy);
      default: throw new Error(`Unknown engine: ${policy.engine}`);
    }
  }

  access(protectedValue, policyName) {
    if (policyName) {
      // Explicit policy
      const policy = this._getPolicy(policyName);
      return this._accessFpe(protectedValue, policy);
    }

    // Tag-based lookup — check longest tags first
    const tags = Object.keys(this._tagIndex).sort((a, b) => b.length - a.length);
    for (const tag of tags) {
      if (protectedValue.startsWith(tag)) {
        const policy = this._getPolicy(this._tagIndex[tag]);
        return this._accessFpe(protectedValue, policy);
      }
    }

    throw new Error("No matching tag found. Use access(value, policyName) for untagged values.");
  }

  // ── FPE protect ──

  _protectFpe(value, policy, isFF3) {
    const key = this._resolveKey(policy.keyRef);
    const alphabet = policy.alphabet;

    // 1. Strip passthroughs
    const { encryptable, positions, chars } = this._extractPassthroughs(value, alphabet);

    // 2. Check zero encryptable
    if (encryptable.length === 0) {
      throw new Error("No encryptable characters in input");
    }

    // 3. Encrypt
    let encrypted;
    if (isFF3) {
      const cipher = new FF3(key, Buffer.alloc(8), alphabet);
      encrypted = cipher.encrypt(encryptable);
    } else {
      const cipher = new FF1(key, Buffer.alloc(0), alphabet);
      encrypted = cipher.encrypt(encryptable);
    }

    // 4. Reinsert passthroughs
    const withPt = this._reinsertPassthroughs(encrypted, positions, chars);

    // 5. Prepend tag
    if (policy.tagEnabled && policy.tag) {
      return policy.tag + withPt;
    }
    return withPt;
  }

  // ── FPE access ──

  _accessFpe(protectedValue, policy) {
    if (!["ff1", "ff3"].includes(policy.engine)) {
      throw new Error(`Cannot reverse '${policy.engine}' — not reversible`);
    }

    const key = this._resolveKey(policy.keyRef);
    const alphabet = policy.alphabet;

    // 1. Strip tag
    let withoutTag = protectedValue;
    if (policy.tagEnabled && policy.tag) {
      withoutTag = protectedValue.slice(policy.tag.length);
    }

    // 2. Strip passthroughs
    const { encryptable, positions, chars } = this._extractPassthroughs(withoutTag, alphabet);

    // 3. Decrypt
    let decrypted;
    if (policy.engine === "ff3") {
      const cipher = new FF3(key, Buffer.alloc(8), alphabet);
      decrypted = cipher.decrypt(encryptable);
    } else {
      const cipher = new FF1(key, Buffer.alloc(0), alphabet);
      decrypted = cipher.decrypt(encryptable);
    }

    // 4. Reinsert passthroughs
    return this._reinsertPassthroughs(decrypted, positions, chars);
  }

  // ── Mask ──

  _protectMask(value, policy) {
    if (!policy.pattern) throw new Error("Mask policy requires 'pattern'");
    const len = value.length;
    const mask = "*";

    switch (policy.pattern) {
      case "last4": case "last_4":
        return mask.repeat(Math.max(0, len - 4)) + value.slice(-4);
      case "last2": case "last_2":
        return mask.repeat(Math.max(0, len - 2)) + value.slice(-2);
      case "first1": case "first_1":
        return value.slice(0, 1) + mask.repeat(Math.max(0, len - 1));
      case "first3": case "first_3":
        return value.slice(0, 3) + mask.repeat(Math.max(0, len - 3));
      case "full":
      default:
        return mask.repeat(len);
    }
  }

  // ── Hash ──

  _protectHash(value, policy) {
    const algo = policy.algorithm.replace("-", "").toLowerCase();
    let javaAlgo;
    switch (algo) {
      case "sha256": javaAlgo = "sha256"; break;
      case "sha384": javaAlgo = "sha384"; break;
      case "sha512": javaAlgo = "sha512"; break;
      default: throw new Error(`Unsupported hash algorithm: ${policy.algorithm}`);
    }

    if (policy.keyRef) {
      const key = this._resolveKey(policy.keyRef);
      const hmac = crypto.createHmac(javaAlgo, key);
      hmac.update(value, "utf8");
      return hmac.digest("hex");
    }

    const hash = crypto.createHash(javaAlgo);
    hash.update(value, "utf8");
    return hash.digest("hex");
  }

  // ── Helpers ──

  _getPolicy(name) {
    const p = this._policies[name];
    if (!p) throw new Error(`Unknown policy: ${name}`);
    return p;
  }

  _resolveKey(keyRef) {
    if (!keyRef) throw new Error("No key_ref in policy");
    const key = this._keys[keyRef];
    if (!key) throw new Error(`Unknown key: ${keyRef}`);
    return key;
  }

  _extractPassthroughs(value, alphabet) {
    let encryptable = "";
    const positions = [];
    const chars = [];

    for (let i = 0; i < value.length; i++) {
      if (alphabet.includes(value[i])) {
        encryptable += value[i];
      } else {
        positions.push(i);
        chars.push(value[i]);
      }
    }

    return { encryptable, positions, chars };
  }

  _reinsertPassthroughs(encrypted, positions, chars) {
    let result = encrypted;
    for (let i = 0; i < positions.length; i++) {
      const pos = positions[i];
      if (pos <= result.length) {
        result = result.slice(0, pos) + chars[i] + result.slice(pos);
      } else {
        result += chars[i];
      }
    }
    return result;
  }
}

module.exports = { Cyphera, ALPHABETS };
