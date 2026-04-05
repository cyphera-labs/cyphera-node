# cyphera

Data obfuscation SDK for Node.js. FPE, AES, masking, hashing. Zero dependencies.

```
npm install cyphera
```

```javascript
const { FF1, DIGITS } = require("cyphera");

const cipher = new FF1(key, tweak, DIGITS);
const encrypted = cipher.encrypt("0123456789");
const decrypted = cipher.decrypt(encrypted);
```

## Status

Early development. FF1 and FF3 engines with all NIST test vectors. Pure JS, no native deps.

## License

Apache 2.0
