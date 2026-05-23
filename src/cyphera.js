"use strict";
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const { FF1 } = require("./ff1");
const { FF3, FF31 } = require("./ff3");

let _ff3Warned = false;
// warnFF3Deprecated emits the FF3 deprecation warning to stderr, once per
// process. Original FF3 is cryptographically weak; use the 'ff31' engine.
function warnFF3Deprecated() {
  if (!_ff3Warned) {
    _ff3Warned = true;
    process.stderr.write(
      "WARNING: engine 'ff3' is deprecated and cryptographically weak — migrate to 'ff31' (FF3-1).\n"
    );
  }
}

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

// Built-in key source resolvers (no keychain dependency needed)
const BUILTIN_SOURCES = {
  env(name, config) {
    const varName = config.var;
    if (!varName) throw new Error(`Key '${name}': source 'env' requires 'var' field`);
    const val = process.env[varName];
    if (!val) throw new Error(`Key '${name}': environment variable '${varName}' is not set`);
    const encoding = config.encoding || "hex";
    if (encoding === "base64") return Buffer.from(val, "base64");
    return Buffer.from(val, "hex");
  },

  file(name, config) {
    const filePath = config.path;
    if (!filePath) throw new Error(`Key '${name}': source 'file' requires 'path' field`);
    const raw = fs.readFileSync(filePath, "utf8").trim();
    const encoding = config.encoding || (filePath.endsWith(".b64") || filePath.endsWith(".base64") ? "base64" : "hex");
    if (encoding === "base64") return Buffer.from(raw, "base64");
    return Buffer.from(raw, "hex");
  },
};

// Cloud sources that require keychain
const CLOUD_SOURCES = ["aws-kms", "gcp-kms", "azure-kv", "vault"];

let _keychain = null;
function getKeychain() {
  if (_keychain === undefined) return null;
  if (_keychain) return _keychain;
  try {
    _keychain = require("@cyphera/keychain");
  } catch {
    _keychain = undefined;
  }
  return _keychain || null;
}

function resolveKeySource(name, config) {
  const source = config.source;

  // Built-in resolvers
  if (BUILTIN_SOURCES[source]) {
    return BUILTIN_SOURCES[source](name, config);
  }

  // Cloud sources — delegate to keychain
  if (CLOUD_SOURCES.includes(source)) {
    const keychain = getKeychain();
    if (!keychain || !keychain.resolve) {
      throw new Error(
        `Key '${name}' requires source '${source}' but @cyphera/keychain is not installed.\n` +
        `Install it: npm install @cyphera/keychain`
      );
    }
    return keychain.resolve(source, config);
  }

  throw new Error(`Key '${name}': unknown source '${source}'. Valid sources: env, file, ${CLOUD_SOURCES.join(", ")}`);
}

class Cyphera {
  constructor(config) {
    this._configurations = {};
    this._headerIndex = {};
    this._keys = {};

    // Load keys
    const keys = config.keys || {};
    for (const [name, val] of Object.entries(keys)) {
      if (typeof val === "string") {
        // Shorthand: bare hex string
        this._keys[name] = Buffer.from(val, "hex");
      } else if (val.material) {
        // Inline hex material
        this._keys[name] = Buffer.from(val.material, "hex");
      } else if (val.source) {
        // Resolve from source
        this._keys[name] = resolveKeySource(name, val);
      } else {
        throw new Error(`Key '${name}' must have either 'material' or 'source'`);
      }
    }

    // Load configurations + build header index
    const configurations = config.configurations || {};
    for (const [name, cfg] of Object.entries(configurations)) {
      const headerEnabled = cfg.header_enabled !== false; // default true
      const header = cfg.header || null;

      if (headerEnabled && !header) {
        throw new Error("configuration error: header must be specified");
      }

      if (headerEnabled && header) {
        if (this._headerIndex[header]) {
          throw new Error("configuration error: header collision");
        }
        this._headerIndex[header] = name;
      }

      this._configurations[name] = {
        engine: cfg.engine || "ff1",
        alphabet: resolveAlphabet(cfg.alphabet),
        keyRef: cfg.key_ref || null,
        header,
        headerEnabled,
        headerLength: cfg.header_length || 3,
        pattern: cfg.pattern || null,
        algorithm: cfg.algorithm || "sha256",
      };
    }
  }

  protect(value, configurationName) {
    const configuration = this._getConfiguration(configurationName);

    switch (configuration.engine) {
      case "ff1":
      case "ff3":
      case "ff31": return this._protectFpe(value, configuration);
      case "mask": return this._protectMask(value, configuration);
      case "hash": return this._protectHash(value, configuration);
      default: throw new Error(`unknown engine: ${configuration.engine}`);
    }
  }

  access(value, configurationName) {
    // Reverse a protected value.
    //
    // The primary, one-argument form `access(value)` is header-driven:
    // the SDK checks the leading bytes of `value` against the registered
    // headers (longest first to avoid prefix collisions), strips the
    // matched header, and decrypts.
    //
    // The two-argument form `access(value, configurationName)` is an
    // escape hatch for unique situations where the protected value has
    // no header (mainframe formats, fixed-width legacy systems, etc.).
    // The caller names the configuration explicitly; `value` is
    // decrypted as raw headerless ciphertext. There is no
    // `header_enabled` guard — the caller asserts the input has no
    // header.
    if (configurationName !== undefined) {
      // Escape-hatch form — caller names the configuration explicitly.
      const configuration = this._getConfiguration(configurationName);
      if (configuration.engine === "mask") {
        throw new Error(`cannot reverse '${configurationName}' — mask is irreversible`);
      }
      if (configuration.engine === "hash") {
        throw new Error(`cannot reverse '${configurationName}' — hash is irreversible`);
      }
      return this._accessFpe(value, configuration);
    }

    // Primary form — header-based lookup, longest headers first.
    const headers = Object.keys(this._headerIndex).sort((a, b) => b.length - a.length);
    for (const header of headers) {
      if (value.startsWith(header)) {
        const configuration = this._getConfiguration(this._headerIndex[header]);
        const stripped = value.slice(header.length);
        return this._accessFpe(stripped, configuration);
      }
    }

    throw new Error("no matching header found");
  }

  // ── FPE protect ──

  _protectFpe(value, configuration) {
    const key = this._resolveKey(configuration.keyRef);
    const alphabet = configuration.alphabet;

    // 1. Strip passthroughs
    const { encryptable, positions, chars } = this._extractPassthroughs(value, alphabet);

    // 2. Check zero encryptable
    if (encryptable.length === 0) {
      throw new Error("no encryptable characters in input");
    }

    // 3. Encrypt
    let encrypted;
    if (configuration.engine === "ff3") {
      warnFF3Deprecated();
      const cipher = new FF3(key, Buffer.alloc(8), alphabet);
      encrypted = cipher.encrypt(encryptable);
    } else if (configuration.engine === "ff31") {
      const cipher = new FF31(key, Buffer.alloc(7), alphabet);
      encrypted = cipher.encrypt(encryptable);
    } else {
      const cipher = new FF1(key, Buffer.alloc(0), alphabet);
      encrypted = cipher.encrypt(encryptable);
    }

    // 4. Reinsert passthroughs
    const withPt = this._reinsertPassthroughs(encrypted, positions, chars);

    // 5. Prepend header
    if (configuration.headerEnabled && configuration.header) {
      return configuration.header + withPt;
    }
    return withPt;
  }

  // ── FPE access ──

  // Internal: decrypt assuming `protectedValue` is already header-stripped.
  // Used by access(value) (which strips the header itself) and by the
  // access(value, name) escape hatch (where the caller asserts the input
  // has no header).
  _accessFpe(protectedValue, configuration) {
    if (!["ff1", "ff3", "ff31"].includes(configuration.engine)) {
      throw new Error(`unknown engine: ${configuration.engine}`);
    }

    const key = this._resolveKey(configuration.keyRef);
    const alphabet = configuration.alphabet;

    // 1. Strip passthroughs
    const { encryptable, positions, chars } = this._extractPassthroughs(protectedValue, alphabet);

    // 2. Decrypt
    let decrypted;
    if (configuration.engine === "ff3") {
      warnFF3Deprecated();
      const cipher = new FF3(key, Buffer.alloc(8), alphabet);
      decrypted = cipher.decrypt(encryptable);
    } else if (configuration.engine === "ff31") {
      const cipher = new FF31(key, Buffer.alloc(7), alphabet);
      decrypted = cipher.decrypt(encryptable);
    } else {
      const cipher = new FF1(key, Buffer.alloc(0), alphabet);
      decrypted = cipher.decrypt(encryptable);
    }

    // 3. Reinsert passthroughs
    return this._reinsertPassthroughs(decrypted, positions, chars);
  }

  // ── Mask ──

  _protectMask(value, configuration) {
    if (!configuration.pattern) throw new Error("mask pattern required");
    const len = value.length;
    const mask = "*";

    switch (configuration.pattern) {
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

  _protectHash(value, configuration) {
    const algo = configuration.algorithm.replace("-", "").toLowerCase();
    let javaAlgo;
    switch (algo) {
      case "sha256": javaAlgo = "sha256"; break;
      case "sha384": javaAlgo = "sha384"; break;
      case "sha512": javaAlgo = "sha512"; break;
      default: throw new Error(`Unsupported hash algorithm: ${configuration.algorithm}`);
    }

    if (configuration.keyRef) {
      const key = this._resolveKey(configuration.keyRef);
      const hmac = crypto.createHmac(javaAlgo, key);
      hmac.update(value, "utf8");
      return hmac.digest("hex");
    }

    const hash = crypto.createHash(javaAlgo);
    hash.update(value, "utf8");
    return hash.digest("hex");
  }

  // ── Helpers ──

  _getConfiguration(name) {
    const c = this._configurations[name];
    if (!c) throw new Error(`configuration not found: ${name}`);
    return c;
  }

  _resolveKey(keyRef) {
    if (!keyRef) throw new Error("key error: no key_ref in configuration");
    const key = this._keys[keyRef];
    if (!key) throw new Error(`key error: key '${keyRef}' not found`);
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

/**
 * Load from a JSON file path.
 */
Cyphera.fromFile = function (filePath) {
  const contents = fs.readFileSync(filePath, "utf8");
  const config = JSON.parse(contents);
  return new Cyphera(config);
};

/**
 * Auto-discover configuration file using standard precedence:
 * 1. CYPHERA_CONFIG_FILE env var
 * 2. ./cyphera.json
 * 3. /etc/cyphera/cyphera.json
 */
Cyphera.load = function () {
  const envPath = process.env.CYPHERA_CONFIG_FILE;
  if (envPath && fs.existsSync(envPath)) {
    return Cyphera.fromFile(envPath);
  }

  const localPath = path.resolve("cyphera.json");
  if (fs.existsSync(localPath)) {
    return Cyphera.fromFile(localPath);
  }

  const systemPath = "/etc/cyphera/cyphera.json";
  if (fs.existsSync(systemPath)) {
    return Cyphera.fromFile(systemPath);
  }

  throw new Error(
    "No configuration file found. Checked: CYPHERA_CONFIG_FILE env, ./cyphera.json, /etc/cyphera/cyphera.json"
  );
};

module.exports = { Cyphera, ALPHABETS };
