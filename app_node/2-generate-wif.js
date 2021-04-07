var CryptoJS = require('cryptojs').Crypto;
var bs58 = require('bs58');

// Private Key prefix
// '80' for mainnet
// 'EF' for testnet
var version = '80';

var privateKey = process.argv[2];

var uncompVersionAndPrivateKey = version + privateKey;
var compVersionAndPrivateKey = version + privateKey + '01';

var uncompFirstSHA256 = CryptoJS.SHA256(CryptoJS.util.hexToBytes(uncompVersionAndPrivateKey));
var compFirstSHA256 = CryptoJS.SHA256(CryptoJS.util.hexToBytes(compVersionAndPrivateKey));

var uncompSecondSHA256 = CryptoJS.SHA256(CryptoJS.util.hexToBytes(uncompFirstSHA256));
var compSecondSHA256 = CryptoJS.SHA256(CryptoJS.util.hexToBytes(compFirstSHA256));

var uncompChecksum = uncompSecondSHA256.substr(0,8).toUpperCase();
var compChecksum = compSecondSHA256.substr(0,8).toUpperCase();

var uncompWif = uncompVersionAndPrivateKey + uncompChecksum;
var compWif = compVersionAndPrivateKey + compChecksum;

var uncompFinalWif = bs58.encode(CryptoJS.util.hexToBytes(uncompWif));
var compFinalWif = bs58.encode(CryptoJS.util.hexToBytes(compWif));

console.log("");
console.log(" ###########################################################################");
console.log(" #                                                                         #");
console.log(" #                  ( Private Key WIF Uncompressed )                       #");
console.log(" #             ( 51 characters base58, starts with a '5' )                 #");
console.log(" #                                                                         #");
console.log(" #         ", uncompFinalWif, "           #");
console.log(" #                                                                         #");
console.log(" ###########################################################################");
console.log("");
console.log(" ###########################################################################");
console.log(" #                                                                         #");
console.log(" #                   ( Private Key WIF Compressed )                        #");
console.log(" #          ( 52 characters base58, starts with a 'K' or 'L' )             #");
console.log(" #                                                                         #");
console.log(" #         ", compFinalWif, "          #");
console.log(" #                                                                         #");
console.log(" ###########################################################################");
