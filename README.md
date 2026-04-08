# cyphera

Data protection SDK for Node.js — format-preserving encryption (FF1/FF3), AES-GCM, data masking, and hashing. Zero dependencies.

```
npm install cyphera
```

## Usage

```javascript
const { Cyphera } = require("cyphera");

// Auto-discover: checks CYPHERA_POLICY_FILE env, ./cyphera.json, /etc/cyphera/cyphera.json
const c = Cyphera.load();

// Or load from a specific file
const c = Cyphera.fromFile("./config/cyphera.json");

// Or inline config
const c = new Cyphera({
  policies: {
    ssn: { engine: "ff1", key_ref: "my-key", tag: "T01" },
  },
  keys: {
    "my-key": { material: "2B7E151628AED2A6ABF7158809CF4F3C" },
  },
});

// Protect
const encrypted = c.protect("123-45-6789", "ssn");
// → "T01i6J-xF-07pX" (tagged, dashes preserved)

// Access (tag-based, no policy name needed)
const decrypted = c.access(encrypted);
// → "123-45-6789"
```

## Policy File (cyphera.json)

```json
{
  "policies": {
    "ssn": { "engine": "ff1", "key_ref": "my-key", "tag": "T01" },
    "cc": { "engine": "ff1", "key_ref": "my-key", "tag": "T02" },
    "ssn_mask": { "engine": "mask", "pattern": "last4", "tag_enabled": false }
  },
  "keys": {
    "my-key": { "material": "2B7E151628AED2A6ABF7158809CF4F3C" }
  }
}
```

## Cross-Language Compatible

Java, Rust, and Node produce identical output for the same inputs:

```
Input:       123-45-6789
Java:        T01i6J-xF-07pX
Rust:        T01i6J-xF-07pX
Node:        T01i6J-xF-07pX
```

## Status

Alpha. API is unstable. Zero runtime dependencies — pure Node.js `crypto` module.

## License

Apache 2.0 — Copyright 2026 Horizon Digital Engineering LLC
