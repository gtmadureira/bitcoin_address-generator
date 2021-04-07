var CryptoJS = require('cryptojs').Crypto

// Step 1 - create a variable with 32 random bytes.

var privateKey = CryptoJS.util.randomBytes(32)

var privateKeyHex = CryptoJS.util.bytesToHex(privateKey).toUpperCase()

// console.log(privateKey)
console.log(privateKeyHex)
