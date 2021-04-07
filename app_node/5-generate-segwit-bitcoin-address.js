var CryptoJS = require('cryptojs').Crypto
var bs58 = require('bs58')
var ec = require('eccrypto')
var bitcoin = require('bitcoinjs-lib')
var segwit_addr = require('./segwit_addr.js')

// P2SH on the main network is 0x05, P2SH on the test network is 0xC4.
// Full list at https://en.bitcoin.it/wiki/List_of_address_prefixes.
var version = '05'

// puts the second command line argument in the variable privateKey.
var privateKey = process.argv[2]

// step 1
var compPublicKeyBytes = ec.getPublicCompressed(Buffer.from(CryptoJS.util.hexToBytes(privateKey)))

// step 2
var compPublicKeySHA256 = CryptoJS.SHA256(compPublicKeyBytes)

// step 3
var compHash160 = bitcoin.crypto.ripemd160(Buffer.from(CryptoJS.util.hexToBytes(compPublicKeySHA256)))

// step 4 - Placing compHash160 in a P2WPKH_VO script
var P2WPKH_VO = '0014' + CryptoJS.util.bytesToHex(compHash160)

// step 5 - Hashing P2WPKH_VO script
var sha256_P2WPKH_VO = CryptoJS.SHA256(CryptoJS.util.hexToBytes(P2WPKH_VO))
var hashed_P2WPKH_VO = bitcoin.crypto.ripemd160(Buffer.from(CryptoJS.util.hexToBytes(sha256_P2WPKH_VO)))

// step 6 - add version in front
var compHashAndBytes = Array.prototype.slice.call(hashed_P2WPKH_VO, 0)
compHashAndBytes.unshift(CryptoJS.util.hexToBytes(version))

// step 7 - first sha256 hash from step 4
var compFirstSHA = CryptoJS.SHA256(compHashAndBytes)

// step 8 - sha256 hash from step 5
var compSecondSHA = CryptoJS.SHA256(CryptoJS.util.hexToBytes(compFirstSHA))

// step 9 - extracts the first 4 bytes to use as checksum
var compChecksum = compSecondSHA.substr(0,8)

// step 10 - version + step 3 + step 7
var compAddress = version + CryptoJS.util.bytesToHex(hashed_P2WPKH_VO) + compChecksum

// step 11 - code result of step 8 in base58
var compFinalAddress = bs58.encode(CryptoJS.util.hexToBytes(compAddress))

console.log("")
console.log(" ###########################################################################")
console.log(" #                                                                         #")
console.log(" #                  Bitcoin SegWit (P2SH-P2WPKH) Address                   #")
console.log(" #                                                                         #")
console.log(" #                  ", compFinalAddress, "                   #")
console.log(" #                                                                         #")
console.log(" ###########################################################################")
console.log("")
console.log(" ###########################################################################")
console.log(" #                                                                         #")
console.log(" #          Bitcoin Native SegWit (Bech32-encoded P2WPKH) Address          #")
console.log(" #                                                                         #")
console.log(" #              ", segwit_addr.encode('bc', 0, compHash160), "               #")
console.log(" #                                                                         #")
console.log(" ###########################################################################")
console.log("")
