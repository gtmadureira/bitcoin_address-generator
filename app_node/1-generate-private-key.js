var CryptoJS = require('cryptojs').Crypto

// Passo 1: Criar uma variavel  com 32 bytes ramdomicos.

var privateKey = CryptoJS.util.randomBytes(32)

var privateKeyHex = CryptoJS.util.bytesToHex(privateKey).toUpperCase()

// console.log(privateKey)
console.log(privateKeyHex)
