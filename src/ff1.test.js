const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const { FF1, DIGITS, ALPHANUMERIC } = require("./ff1");

const hex = (s) => Buffer.from(s, "hex");

describe("FF1 NIST Vectors", () => {
  it("sample 1", () => { const c = new FF1(hex("2B7E151628AED2A6ABF7158809CF4F3C"), Buffer.alloc(0), DIGITS); assert.equal(c.encrypt("0123456789"), "2433477484"); assert.equal(c.decrypt("2433477484"), "0123456789"); });
  it("sample 2", () => { const c = new FF1(hex("2B7E151628AED2A6ABF7158809CF4F3C"), hex("39383736353433323130"), DIGITS); assert.equal(c.encrypt("0123456789"), "6124200773"); assert.equal(c.decrypt("6124200773"), "0123456789"); });
  it("sample 3", () => { const c = new FF1(hex("2B7E151628AED2A6ABF7158809CF4F3C"), hex("3737373770717273373737"), ALPHANUMERIC); assert.equal(c.encrypt("0123456789abcdefghi"), "a9tv40mll9kdu509eum"); assert.equal(c.decrypt("a9tv40mll9kdu509eum"), "0123456789abcdefghi"); });
  it("sample 4", () => { const c = new FF1(hex("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F"), Buffer.alloc(0), DIGITS); assert.equal(c.encrypt("0123456789"), "2830668132"); assert.equal(c.decrypt("2830668132"), "0123456789"); });
  it("sample 5", () => { const c = new FF1(hex("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F"), hex("39383736353433323130"), DIGITS); assert.equal(c.encrypt("0123456789"), "2496655549"); assert.equal(c.decrypt("2496655549"), "0123456789"); });
  it("sample 6", () => { const c = new FF1(hex("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F"), hex("3737373770717273373737"), ALPHANUMERIC); assert.equal(c.encrypt("0123456789abcdefghi"), "xbj3kv35jrawxv32ysr"); assert.equal(c.decrypt("xbj3kv35jrawxv32ysr"), "0123456789abcdefghi"); });
  it("sample 7", () => { const c = new FF1(hex("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94"), Buffer.alloc(0), DIGITS); assert.equal(c.encrypt("0123456789"), "6657667009"); assert.equal(c.decrypt("6657667009"), "0123456789"); });
  it("sample 8", () => { const c = new FF1(hex("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94"), hex("39383736353433323130"), DIGITS); assert.equal(c.encrypt("0123456789"), "1001623463"); assert.equal(c.decrypt("1001623463"), "0123456789"); });
  it("sample 9", () => { const c = new FF1(hex("2B7E151628AED2A6ABF7158809CF4F3CEF4359D8D580AA4F7F036D6F04FC6A94"), hex("3737373770717273373737"), ALPHANUMERIC); assert.equal(c.encrypt("0123456789abcdefghi"), "xs8a0azh2avyalyzuwd"); assert.equal(c.decrypt("xs8a0azh2avyalyzuwd"), "0123456789abcdefghi"); });
});
