#!/bin/zsh
clear
gen=$(node 1-generate-private-key.js)
genb64=$(echo $gen | xxd -r -p | base64)
echo ''
echo ' ###########################################################################'
echo ' #                                                                         #'
echo ' #        Private Key Hexadecimal Format (64 characters [0-9A-F])          #'
echo ' #                                                                         #'
echo ' #     '$gen'    #'
echo ' #                                                                         #'
echo ' ###########################################################################'
echo ''
echo ' ###########################################################################'
echo ' #                                                                         #'
echo ' #                    Private Key Base64 (44 characters)                   #'
echo ' #                                                                         #'
echo ' #              '$genb64'               #'
echo ' #                                                                         #'
echo ' ###########################################################################'
node 2-generate-wif.js $gen
node 3-generate-public-key.js $gen
node 4-generate-legacy-bitcoin-address.js $gen
node 5-generate-segwit-bitcoin-address.js $gen
