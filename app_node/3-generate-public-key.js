var CryptoJS = require('cryptojs').Crypto;
var ec = require('eccrypto');

var privateKey = process.argv[2];

var uncompPublicKey = ec.getPublic(Buffer.from(CryptoJS.util.hexToBytes(privateKey)));
var compPublicKey = ec.getPublicCompressed(Buffer.from(CryptoJS.util.hexToBytes(privateKey)));

console.log("");
console.log(" ###########################################################################");
console.log(" #                                                                         #");
console.log(" #          Public Key (uncompressed, 130 characters [0-9A-F])             #");
console.log(" #                                                                         #");
console.log(" #   ", CryptoJS.util.bytesToHex(uncompPublicKey).substr(0,65).toUpperCase(), "   #");
console.log(" #   ", CryptoJS.util.bytesToHex(uncompPublicKey).substr(65,130).toUpperCase(), "   #");
console.log(" #                                                                         #");
console.log(" ###########################################################################");
console.log("");
console.log(" ###########################################################################");
console.log(" #                                                                         #");
console.log(" #            Public Key (compressed, 66 characters [0-9A-F])              #");
console.log(" #                                                                         #");
console.log(" #   ", CryptoJS.util.bytesToHex(compPublicKey).toUpperCase(), "  #");
console.log(" #                                                                         #");
console.log(" ###########################################################################");
