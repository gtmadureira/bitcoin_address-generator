# Super simple Elliptic Curve Presentation.
# For educational purposes only.
# Works on Python 3.6.13 or higher.
# Source: https://github.com/gtmadureira/bitcoin_address-generator/blob/main/app_python/PrivKey_to_pubkey/secp256k1.py

import hashlib
import os
import sys
import randpass

# Checking the type of Operating System.
if sys.platform == "linux" or sys.platform == "linux2" or sys.platform == "darwin":
    def clear(): os.system('clear') # On Linux/OS X System.
elif sys.platform == "win32":
    def clear(): os.system('cls') # On Windows System.

clear()

Password_Size = 1024 # Password length.
Password = randpass.passgen(Password_Size) # Generates a Random Password.

# Hashing Password with SHA3-256 algorithm.
HashedPassword = hashlib.sha3_256()
HashedPassword.update(Password.encode())

PrivKey = int("0x" + HashedPassword.hexdigest(), 16) # Random Private Key at hex_value.

# secp256k1 domain parameters.
Pcurve = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F # The proven prime.
Acurve = 0x0000000000000000000000000000000000000000000000000000000000000000 # These two defines the elliptic curve.
Bcurve = 0x0000000000000000000000000000000000000000000000000000000000000007 # y^2 = x^3 + int(Acurve) * x + int(Bcurve).
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
GPoint = (int(Gx), int(Gy)) # This is our generator point.
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 # Number of points in the field.

def ModInv(a, b = int(Pcurve)): # Extended Euclidean Algorithm/'division' in elliptic curves.
    lm, hm = 1, 0
    low, high = a % b, b
    while low > 1:
        ratio = high // low
        nm, new = hm - lm * ratio, high - low * ratio
        lm, low, hm, high = nm, new, lm, low
    return lm % b

def ECAdd(a, b): # Point Addition, invented for EC.
    LambdaAdd = ((b[1] - a[1]) * ModInv(b[0] - a[0], int(Pcurve))) % int(Pcurve)
    x = (LambdaAdd * LambdaAdd - a[0] - b[0]) % int(Pcurve)
    y = (LambdaAdd * (a[0] - x) - a[1]) % int(Pcurve)
    return (x, y)

def ECDouble(a): # Point Doubling, invented for EC.
    LamdaDouble = ((3 * a[0] * a[0] + int(Acurve)) * ModInv((2 * a[1]), int(Pcurve))) % int(Pcurve)
    x = (LamdaDouble * LamdaDouble - 2 * a[0]) % int(Pcurve)
    y = (LamdaDouble * (a[0] - x) - a[1]) % int(Pcurve)
    return (x, y)

def ECMultiply(GenPoint, PrivKeyHex): # Doubling & Addition. Not true multiplication.
    if PrivKeyHex == 0 or PrivKeyHex >= N:
        raise Exception("Invalid Private Key")
    PrivKeyBin = str(bin(PrivKeyHex))[2:]
    Q = GenPoint
    for i in range (1, len(PrivKeyBin)):
        Q = ECDouble(Q)
        if PrivKeyBin[i] == "1":
            Q = ECAdd(Q, GenPoint)
    return (Q)

PublicKey = ECMultiply(GPoint, PrivKey)

print ()
print ("--------------------------------------------------------------------------------------------------------------------------------------------")
print ()
print ("  'Random Password' currently set with '" + str(Password_Size) + "' characters:")
print ()
print ("   " + Password[0:128])
print ("   " + Password[128:256])
print ("   " + Password[256:384])
print ("   " + Password[384:512])
print ("   " + Password[512:640])
print ("   " + Password[640:768])
print ("   " + Password[768:896])
print ("   " + Password[896:1024])
print ()
print ("--------------------------------------------------------------------------------------------------------------------------------------------")
print ()
print ("  'Private Key' derived from Hashed 'Random Password' (64 characters hexadecimal [0-9A-F], hashed by SHA3-256):")
print ()
print ("   " + hex(PrivKey)[2:].zfill(64).upper())
print ()
print ("--------------------------------------------------------------------------------------------------------------------------------------------")
print ()
print ("  'Public Key' derived from 'Private Key' using 'secp256k1 elliptic curve' (uncompressed, 130 characters hexadecimal [0-9A-F]):")
print ()
print ("        [prefix = '04'] + [32 bytes of X coordinate] + [32 bytes of Y coordinate]")
print ()
print ("   " + "04" + hex(PublicKey[0])[2:].zfill(64).upper() + hex(PublicKey[1])[2:].zfill(64).upper())
print ()
print ("--------------------------------------------------------------------------------------------------------------------------------------------")
print ()
if PublicKey[1] % 2 == 1: # If the Y coordinate of the Public Key is odd.
    prefix = "'03'"
else: # If the Y coordinate of the Public Key is even.
    prefix = "'02'"
print ("  'Public Key' derived from 'Private Key' using 'secp256k1 elliptic curve' (compressed, 66 characters hexadecimal [0-9A-F]):")
print ()
print ("        [prefix = " + prefix + "] + [32 bytes of X coordinate]")
print ()
if PublicKey[1] % 2 == 1: # If the Y coordinate of the Public Key is odd.
    print ("   " + "03" + hex(PublicKey[0])[2:].zfill(64).upper())
else: # If the Y coordinate of the Public Key is even.
    print ("   " + "02" + hex(PublicKey[0])[2:].zfill(64).upper())
print ()
print ("--------------------------------------------------------------------------------------------------------------------------------------------")
print ()
