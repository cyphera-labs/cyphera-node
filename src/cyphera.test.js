"use strict";
const { describe, it } = require("node:test");
const assert = require("node:assert");
const { Cyphera } = require("./cyphera");

const config = {
  configurations: {
    ssn: { engine: "ff1", key_ref: "test-key", header: "T01" },
    ssn_digits: { engine: "ff1", alphabet: "digits", header_enabled: false, key_ref: "test-key" },
    ssn_mask: { engine: "mask", pattern: "last4", header_enabled: false },
    ssn_hash: { engine: "hash", algorithm: "sha256", key_ref: "test-key", header_enabled: false },
  },
  keys: {
    "test-key": { material: "2B7E151628AED2A6ABF7158809CF4F3C" },
  },
};

describe("Cyphera SDK", () => {
  it("protect and access with header", () => {
    const c = new Cyphera(config);
    const protected_ = c.protect("123456789", "ssn");
    assert.ok(protected_.startsWith("T01"));
    assert.ok(protected_.length > "123456789".length);
    const accessed = c.access(protected_);
    assert.strictEqual(accessed, "123456789");
  });

  it("protect and access with passthroughs", () => {
    const c = new Cyphera(config);
    const protected_ = c.protect("123-45-6789", "ssn");
    assert.ok(protected_.includes("-"));
    const accessed = c.access(protected_);
    assert.strictEqual(accessed, "123-45-6789");
  });

  it("header-less digits roundtrip", () => {
    const c = new Cyphera(config);
    const protected_ = c.protect("123456789", "ssn_digits");
    assert.strictEqual(protected_.length, 9);
    const accessed = c.access(protected_, "ssn_digits");
    assert.strictEqual(accessed, "123456789");
  });

  it("deterministic", () => {
    const c = new Cyphera(config);
    const a = c.protect("123456789", "ssn");
    const b = c.protect("123456789", "ssn");
    assert.strictEqual(a, b);
  });

  it("mask last4", () => {
    const c = new Cyphera(config);
    const result = c.protect("123-45-6789", "ssn_mask");
    assert.strictEqual(result, "*******6789");
  });

  it("hash deterministic", () => {
    const c = new Cyphera(config);
    const a = c.protect("123-45-6789", "ssn_hash");
    const b = c.protect("123-45-6789", "ssn_hash");
    assert.strictEqual(a, b);
    assert.ok(/^[0-9a-f]+$/.test(a));
  });

  it("access non-reversible throws", () => {
    const c = new Cyphera(config);
    const masked = c.protect("123-45-6789", "ssn_mask");
    assert.throws(() => c.access(masked), /no matching header found/);
  });

  it("access with config: unknown configuration throws", () => {
    const c = new Cyphera(config);
    assert.throws(() => c.access("abc", "nope"));
  });

  it("access with config: irreversible engine throws", () => {
    const c = new Cyphera(config);
    // Escape hatch rejects irreversible engines (mask/hash).
    assert.throws(() => c.access("anything", "ssn_mask"), /mask is irreversible/);
  });

  it("header collision throws", () => {
    assert.throws(() => new Cyphera({
      configurations: {
        a: { engine: "ff1", key_ref: "k", header: "ABC" },
        b: { engine: "ff1", key_ref: "k", header: "ABC" },
      },
      keys: { k: { material: "2B7E151628AED2A6ABF7158809CF4F3C" } },
    }), /configuration error: header collision/);
  });

  it("header required when enabled throws", () => {
    assert.throws(() => new Cyphera({
      configurations: {
        a: { engine: "ff1", key_ref: "k" },
      },
      keys: { k: { material: "2B7E151628AED2A6ABF7158809CF4F3C" } },
    }), /configuration error: header must be specified/);
  });

  it("unicode passthroughs roundtrip", () => {
    const c = new Cyphera(config);
    const protected_ = c.protect("José123456", "ssn");
    const accessed = c.access(protected_);
    assert.strictEqual(accessed, "José123456");
  });

  it("key source: env", () => {
    process.env.TEST_CYPHERA_KEY = "2B7E151628AED2A6ABF7158809CF4F3C";
    const c = new Cyphera({
      configurations: { ssn: { engine: "ff1", key_ref: "k", header: "T01" } },
      keys: { k: { source: "env", var: "TEST_CYPHERA_KEY" } },
    });
    const p = c.protect("123456789", "ssn");
    assert.ok(p.startsWith("T01"));
    assert.strictEqual(c.access(p), "123456789");
    delete process.env.TEST_CYPHERA_KEY;
  });

  it("key source: env base64", () => {
    process.env.TEST_CYPHERA_KEY_B64 = Buffer.from("2B7E151628AED2A6ABF7158809CF4F3C", "hex").toString("base64");
    const c = new Cyphera({
      configurations: { ssn: { engine: "ff1", key_ref: "k", header: "T01" } },
      keys: { k: { source: "env", var: "TEST_CYPHERA_KEY_B64", encoding: "base64" } },
    });
    const p = c.protect("123456789", "ssn");
    assert.ok(p.startsWith("T01"));
    assert.strictEqual(c.access(p), "123456789");
    delete process.env.TEST_CYPHERA_KEY_B64;
  });

  it("key source: env missing var throws", () => {
    delete process.env.NONEXISTENT_KEY;
    assert.throws(() => new Cyphera({
      configurations: { ssn: { engine: "ff1", key_ref: "k", header: "T01" } },
      keys: { k: { source: "env", var: "NONEXISTENT_KEY" } },
    }), /not set/);
  });

  it("key source: file", () => {
    const tmpFile = "/tmp/cyphera-test-key.hex";
    require("fs").writeFileSync(tmpFile, "2B7E151628AED2A6ABF7158809CF4F3C");
    const c = new Cyphera({
      configurations: { ssn: { engine: "ff1", key_ref: "k", header: "T01" } },
      keys: { k: { source: "file", path: tmpFile } },
    });
    const p = c.protect("123456789", "ssn");
    assert.ok(p.startsWith("T01"));
    assert.strictEqual(c.access(p), "123456789");
    require("fs").unlinkSync(tmpFile);
  });

  it("key source: unknown cloud source without keychain throws", () => {
    assert.throws(() => new Cyphera({
      configurations: { ssn: { engine: "ff1", key_ref: "k", header: "T01" } },
      keys: { k: { source: "aws-kms", arn: "arn:aws:kms:us-east-1:123:key/abc" } },
    }), /cyphera\/keychain/);
  });

  it("key source: unknown source throws", () => {
    assert.throws(() => new Cyphera({
      configurations: { ssn: { engine: "ff1", key_ref: "k", header: "T01" } },
      keys: { k: { source: "magic", foo: "bar" } },
    }), /unknown source/);
  });

  it("key source: env produces same output as inline material", () => {
    process.env.TEST_CYPHERA_KEY2 = "2B7E151628AED2A6ABF7158809CF4F3C";
    const cInline = new Cyphera(config);
    const cEnv = new Cyphera({
      configurations: config.configurations,
      keys: { "test-key": { source: "env", var: "TEST_CYPHERA_KEY2" } },
    });
    const p1 = cInline.protect("123456789", "ssn");
    const p2 = cEnv.protect("123456789", "ssn");
    assert.strictEqual(p1, p2, "env source should produce identical output to inline material");
    delete process.env.TEST_CYPHERA_KEY2;
  });

  // FF3 / FF3-1 tweak is required at the configuration layer. Missing → hard
  // error with the canonical spec message. No silent zero-fill (matches NIST
  // + Bouncy Castle + cyphera-rust).
  const keyOnly = { "test-key": { material: "2B7E151628AED2A6ABF7158809CF4F3C" } };

  it("protect FF3 without tweak throws canonical message", () => {
    const c = new Cyphera({
      configurations: {
        ff3_d: { engine: "ff3", alphabet: "digits", key_ref: "test-key", header_enabled: false },
      },
      keys: keyOnly,
    });
    assert.throws(
      () => c.protect("0123456789", "ff3_d"),
      (err) => err.message === "configuration 'ff3_d' is missing required 'tweak' (FF3 needs 8 bytes)"
    );
  });

  it("protect FF3-1 without tweak throws canonical message", () => {
    const c = new Cyphera({
      configurations: {
        ff31_d: { engine: "ff31", alphabet: "digits", key_ref: "test-key", header_enabled: false },
      },
      keys: keyOnly,
    });
    assert.throws(
      () => c.protect("0123456789", "ff31_d"),
      (err) => err.message === "configuration 'ff31_d' is missing required 'tweak' (FF3-1 needs 7 bytes)"
    );
  });

  it("protect FF1 without tweak is fine (NIST allows arbitrary length)", () => {
    const c = new Cyphera({
      configurations: {
        ff1_d: { engine: "ff1", alphabet: "digits", key_ref: "test-key", header_enabled: false },
      },
      keys: keyOnly,
    });
    const protected_ = c.protect("0123456789", "ff1_d");
    assert.notStrictEqual(protected_, "0123456789");
  });

  it("protect FF3 with real tweak roundtrips", () => {
    const c = new Cyphera({
      configurations: {
        ff3_d: {
          engine: "ff3",
          alphabet: "digits",
          key_ref: "test-key",
          tweak: "D8E7920AFA330A73",
          header_enabled: false,
        },
      },
      keys: keyOnly,
    });
    const protected_ = c.protect("0123456789", "ff3_d");
    assert.notStrictEqual(protected_, "0123456789");
    assert.strictEqual(c.access(protected_, "ff3_d"), "0123456789");
  });

  it("protect FF3-1 with real tweak roundtrips", () => {
    const c = new Cyphera({
      configurations: {
        ff31_d: {
          engine: "ff31",
          alphabet: "digits",
          key_ref: "test-key",
          tweak: "D8E7920AFA330A",
          header_enabled: false,
        },
      },
      keys: keyOnly,
    });
    const protected_ = c.protect("0123456789", "ff31_d");
    assert.notStrictEqual(protected_, "0123456789");
    assert.strictEqual(c.access(protected_, "ff31_d"), "0123456789");
  });
});
