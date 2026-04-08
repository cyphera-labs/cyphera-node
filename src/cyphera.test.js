"use strict";
const { describe, it } = require("node:test");
const assert = require("node:assert");
const { Cyphera } = require("./cyphera");

const config = {
  policies: {
    ssn: { engine: "ff1", key_ref: "test-key", tag: "T01" },
    ssn_digits: { engine: "ff1", alphabet: "digits", tag_enabled: false, key_ref: "test-key" },
    ssn_mask: { engine: "mask", pattern: "last4", tag_enabled: false },
    ssn_hash: { engine: "hash", algorithm: "sha256", key_ref: "test-key", tag_enabled: false },
  },
  keys: {
    "test-key": { material: "2B7E151628AED2A6ABF7158809CF4F3C" },
  },
};

describe("Cyphera SDK", () => {
  it("protect and access with tag", () => {
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

  it("untagged digits roundtrip", () => {
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
    assert.throws(() => c.access(masked), /No matching tag/);
  });

  it("tag collision throws", () => {
    assert.throws(() => new Cyphera({
      policies: {
        a: { engine: "ff1", key_ref: "k", tag: "ABC" },
        b: { engine: "ff1", key_ref: "k", tag: "ABC" },
      },
      keys: { k: { material: "2B7E151628AED2A6ABF7158809CF4F3C" } },
    }), /Tag collision/);
  });

  it("tag required when enabled throws", () => {
    assert.throws(() => new Cyphera({
      policies: {
        a: { engine: "ff1", key_ref: "k" },
      },
      keys: { k: { material: "2B7E151628AED2A6ABF7158809CF4F3C" } },
    }), /no tag specified/);
  });

  it("unicode passthroughs roundtrip", () => {
    const c = new Cyphera(config);
    const protected_ = c.protect("José123456", "ssn");
    const accessed = c.access(protected_);
    assert.strictEqual(accessed, "José123456");
  });
});
