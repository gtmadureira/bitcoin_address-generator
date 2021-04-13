# Super simple Elliptic Curve Presentation.
# For educational purposes only. Works in Python 3.
# Source: https://github.com/gtmadureira/bitcoin_address-generator/blob/main/app_python/privkey_to_pubkey/secp256k1.py

import random
import array
import hashlib
import os
import sys

# Checking the type of Operating System.
if sys.platform == "linux" or sys.platform == "linux2" or sys.platform == "darwin":
    def clear(): os.system('clear') # On Linux/OS X System
elif sys.platform == "win32":
    def clear(): os.system('cls') # On Windows System

clear()

# Maximum length of password needed.
# This can be changed to suit your password length.
MAX_LEN = 1024

# Declare arrays of the character that we need in out password.
# Represented as chars to enable easy string concatenation.
DIGITS = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']

LOCASE_CHARACTERS = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
					 'i', 'j', 'k', 'm', 'n', 'o', 'p', 'q',
					 'r', 's', 't', 'u', 'v', 'w', 'x', 'y',
					 'z']

UPCASE_CHARACTERS = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
					 'I', 'J', 'K', 'M', 'N', 'O', 'p', 'Q',
					 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y',
					 'Z']

SYMBOLS = [' ', '!', '"', '#', '$', '%', '&', "'", '(', ')', '*',
           '+', ',', '-', '.', '/', ':', ';', '<', '=', '>', '?',
           '@', '[', '\\', ']', '^', '_', '`', '{', '|', '}', '~']

# Combines all the character arrays above to form one array.
COMBINED_LIST = DIGITS + UPCASE_CHARACTERS + LOCASE_CHARACTERS + SYMBOLS

# Randomly select at least one character from each character set above.
rand_digit = random.choice(DIGITS)
rand_upper = random.choice(UPCASE_CHARACTERS)
rand_lower = random.choice(LOCASE_CHARACTERS)
rand_symbol = random.choice(SYMBOLS)

# Combine the character randomly selected above
# at this stage, the password contains only 4 characters but
# we want a 12-character password.
temp_pass = rand_digit + rand_upper + rand_lower + rand_symbol

# Now that we are sure we have at least one character from each
# set of characters, we fill the rest of
# the password length by selecting randomly from the combined
# list of character above.
for x in range(MAX_LEN - 4):
	temp_pass = temp_pass + random.choice(COMBINED_LIST)

	# Convert temporary password into array and shuffle to
	# prevent it from having a consistent pattern
	# where the beginning of the password is predictable.
	temp_pass_list = array.array('u', temp_pass)
	random.shuffle(temp_pass_list)

# Traverse the temporary password array and append the chars
# to form the password.
password = ""
for x in temp_pass_list:
		password = password + x

# Hashing password with SHA3-256 algorithm.
hash = hashlib.sha3_256()
hash.update(password.encode())

privKeyStr = "0x"+hash.hexdigest() # Random Private Key at hex_string.
privKey = int(privKeyStr, 16) # Random Private Key at hex_value.

# secp256k1 domain parameters.
Pcurve = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F # The proven prime.
Acurve = 0x0000000000000000000000000000000000000000000000000000000000000000 # These two defines the elliptic curve. y^2 = x^3 + int(Acurve) * x + int(Bcurve).
Bcurve = 0x0000000000000000000000000000000000000000000000000000000000000007
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
GPoint = (int(Gx),int(Gy)) # This is our generator point.
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 # Number of points in the field.

def modinv(a, b = int(Pcurve)): #Extended Euclidean Algorithm/'division' in elliptic curves.
    lm, hm = 1,0
    low, high = a%b,b
    while low > 1:
        ratio = high//low
        nm, new = hm-lm*ratio, high-low*ratio
        lm, low, hm, high = nm, new, lm, low
    return lm % b

def ECAdd(a,b): # Point Addition, invented for EC.
    LambdaAdd = ((b[1] - a[1]) * modinv(b[0] - a[0],int(Pcurve))) % int(Pcurve)
    x = (LambdaAdd * LambdaAdd - a[0] - b[0]) % int(Pcurve)
    y = (LambdaAdd * (a[0] - x) - a[1]) % int(Pcurve)
    return (x,y)

def ECDouble(a): # Point Doubling, invented for EC.
    LamdaDouble = ((3 * a[0] * a[0] + int(Acurve)) * modinv((2 * a[1]), int(Pcurve))) % int(Pcurve)
    x = (LamdaDouble * LamdaDouble - 2 * a[0]) % int(Pcurve)
    y = (LamdaDouble * (a[0] - x) - a[1]) % int(Pcurve)
    return (x,y)

def ECMultiply(GenPoint,privKeyHex): # Doubling & Addition. Not true multiplication.
    if privKeyHex == 0 or privKeyHex >= N: raise Exception("Invalid Private Key")
    privKeyBin = str(bin(privKeyHex))[2:]
    Q=GenPoint
    for i in range (1, len(privKeyBin)):
        Q=ECDouble(Q);
        if privKeyBin[i] == "1":
            Q=ECAdd(Q,GenPoint);
    return (Q)

publicKey = ECMultiply(GPoint,privKey)

print()
print("--------------------------------------------------------------------------------------------------------------------------------------------")
print()
print("  'Random Password' currently set with '"+str(MAX_LEN)+"' characters:")
print()
print ("  "+password[0:128])
print ("  "+password[128:256])
print ("  "+password[256:384])
print ("  "+password[384:512])
print ("  "+password[512:640])
print ("  "+password[640:768])
print ("  "+password[768:896])
print ("  "+password[896:1024])
print()
print("--------------------------------------------------------------------------------------------------------------------------------------------")
print()
print ("  'Private Key' derived from Hashed 'Random Password' (64 characters hexadecimal [0-9A-F], hashed by SHA3-256):")
print()
print ("  "+str(hex(privKey)[2:]).zfill(32).upper())
print()
print("--------------------------------------------------------------------------------------------------------------------------------------------")
print()
print ("  'Public Key' derived from 'Private Key' using 'secp256k1 elliptic curve' (uncompressed, 130 characters hexadecimal [0-9A-F])")
print ("  [prefix = '04'] + [32 bytes of X coordinate] + [32 bytes of Y coordinate]:")
print()
print ("  "+"04"+str(hex(publicKey[0])[2:]).zfill(64).upper()+str(hex(publicKey[1])[2:]).zfill(64).upper())
print()
print("--------------------------------------------------------------------------------------------------------------------------------------------")
print()
if publicKey[1] % 2 == 1: # If the Y coordinate of the Public Key is odd.
    prefix = "'03'"
else: # If the Y coordinate of the Public Key is even.
    prefix = "'02'"
print ("  'Public Key' derived from 'Private Key' using 'secp256k1 elliptic curve' (compressed, 66 characters hexadecimal [0-9A-F])")
print ("  [prefix = " + prefix + "] + [32 bytes of X coordinate]:")
print()
if publicKey[1] % 2 == 1: # If the Y coordinate of the Public Key is odd.
    print ("  "+"03"+str(hex(publicKey[0])[2:]).zfill(64).upper())
else: # If the Y coordinate of the Public Key is even.
    print ("  "+"02"+str(hex(publicKey[0])[2:]).zfill(64).upper())
print()
print("--------------------------------------------------------------------------------------------------------------------------------------------")
print()
