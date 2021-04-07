var CryptoJS = require('cryptojs').Crypto
var bs58 = require('bs58')
var ec = require('eccrypto')
var bitcoin = require('bitcoinjs-lib')

// P2PKH on the main network is 0x00, P2PKH on the test network is 0x6F.
// Full list at https://en.bitcoin.it/wiki/List_of_address_prefixes.
var version = '00'

// puts the second command line argument in the variable privateKey.
var privateKey = process.argv[2]

// step 1
// uncompressed
var uncompPublicKeyBytes = ec.getPublic(Buffer.from(CryptoJS.util.hexToBytes(privateKey)))
// compressed
var compPublicKeyBytes = ec.getPublicCompressed(Buffer.from(CryptoJS.util.hexToBytes(privateKey)))

// step 2
// uncompressed
var uncompPublicKeySHA256 = CryptoJS.SHA256(uncompPublicKeyBytes)
// compressed
var compPublicKeySHA256 = CryptoJS.SHA256(compPublicKeyBytes)

// step 3
// uncompressed
var uncompHash160 = bitcoin.crypto.ripemd160(Buffer.from(CryptoJS.util.hexToBytes(uncompPublicKeySHA256)))
// compressed
var compHash160 = bitcoin.crypto.ripemd160(Buffer.from(CryptoJS.util.hexToBytes(compPublicKeySHA256)))

// step 4 - add version in front
// uncompressed
var uncompHashAndBytes = Array.prototype.slice.call(uncompHash160, 0)
uncompHashAndBytes.unshift(CryptoJS.util.hexToBytes(version))
// compressed
var compHashAndBytes = Array.prototype.slice.call(compHash160, 0)
compHashAndBytes.unshift(CryptoJS.util.hexToBytes(version))

// step 5 - first sha256 hash from step 4
// uncompressed
var uncompFirstSHA = CryptoJS.SHA256(uncompHashAndBytes)
// compressed
var compFirstSHA = CryptoJS.SHA256(compHashAndBytes)

// step 6 - sha256 hash from step 5
// uncompressed
var uncompSecondSHA = CryptoJS.SHA256(CryptoJS.util.hexToBytes(uncompFirstSHA))
// compressed
var compSecondSHA = CryptoJS.SHA256(CryptoJS.util.hexToBytes(compFirstSHA))

// step 7 - extracts the first 4 bytes to use as checksum
// uncompressed
var uncompChecksum = uncompSecondSHA.substr(0,8)
// compressed
var compChecksum = compSecondSHA.substr(0,8)

// step 8 - version + step 3 + step 7
// uncompressed
var uncompAddress = version + CryptoJS.util.bytesToHex(uncompHash160) + uncompChecksum
// compressed
var compAddress = version + CryptoJS.util.bytesToHex(compHash160) + compChecksum

// step 9 - code result of step 8 in base58
// uncompressed
var uncompFinalAddress = bs58.encode(CryptoJS.util.hexToBytes(uncompAddress))
// compressed
var compFinalAddress = bs58.encode(CryptoJS.util.hexToBytes(compAddress))

console.log("")
console.log(" ###########################################################################")
console.log(" #                                                                         #")
console.log(" #                      Bitcoin Uncompressed Address                       #")
console.log(" #                                                                         #")
console.log(" #                  ", uncompFinalAddress, "                   #")
console.log(" #                                                                         #")
console.log(" ###########################################################################")
console.log("")
console.log(" ###########################################################################")
console.log(" #                                                                         #")
console.log(" #                       Bitcoin Compressed Address                        #")
console.log(" #                                                                         #")
console.log(" #                  ", compFinalAddress, "                   #")
console.log(" #                                                                         #")
console.log(" ###########################################################################")
