# Super simple Elliptic Curve Presentation with signature generation and verification.
# For educational purposes only.
# Works on Python 3.6.13 or higher.
# Source: https://github.com/gtmadureira/bitcoin_address-generator/blob/main/app_python/PrivKey_to_pubkey/signing_and_verifying.py

import hashlib
import os
import sys
import randpass

# Checking the type of Operating System.
if sys.platform == "linux" or sys.platform == "linux2" or sys.platform == "darwin":
    def clear(): os.system('clear') # On Linux/OS X System
elif sys.platform == "win32":
    def clear(): os.system('cls') # On Windows System

clear()

Password_Size = 1024 # Password size.
Password = randpass.passgen(Password_Size) # Generates a Random Password.

# Hashing Password with SHA3-256 algorithm.
HashedPassword = hashlib.sha3_256()
HashedPassword.update(Password.encode())

PrivKey = int("0x" + HashedPassword.hexdigest(), 16) # Random Private Key at hex_value.

RandNum = int("0x" + randpass.numgen(64), 16) # Replace with a truly random hex number.

Message = "May the Force be with you." # The Message/Transaction.
MessageToHash = hashlib.sha3_256()
MessageToHash.update(Message.encode())
HashedMessage = int("0x" + MessageToHash.hexdigest(), 16) # The hash of your Message/transaction.

# secp256k1 domain parameters.
Pcurve = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F # The proven prime.
Acurve = 0x0000000000000000000000000000000000000000000000000000000000000000 # These two defines the elliptic curve.
Bcurve = 0x0000000000000000000000000000000000000000000000000000000000000007 #   y^2 = x^3 + int(Acurve) * x + int(Bcurve).
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
GPoint = (int(Gx), int(Gy)) # This is our generator point.
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 # Number of points in the field.

def ModInv(a, n = int(Pcurve)): # Extended Euclidean Algorithm/'division' in elliptic curves.
    lm, hm = 1, 0
    low, high = a % n, n
    while low > 1:
        ratio = high // low
        nm, new = hm - lm * ratio, high - low * ratio
        lm, low, hm, high = nm, new, lm, low
    return lm % n

def ECAdd(xp, yp, xq, yq): # Not true addition, invented for EC. It adds Point-P with Point-Q.
    m = ((yq - yp) * ModInv(xq - xp, int(Pcurve)) % int(Pcurve))
    xr = (m * m - xp - xq) % int(Pcurve)
    yr = (m * (xp - xr) - yp) % int(Pcurve)
    return (xr, yr)

def ECDouble(xp, yp): # EC point doubling, invented for EC. It doubles Point-P.
    LamNumer = 3 * xp * xp + int(Acurve)
    LamDenom = 2 * yp
    Lam = (LamNumer * ModInv(LamDenom, int(Pcurve))) % int(Pcurve)
    xr = (Lam * Lam - 2 * xp) % int(Pcurve)
    yr = (Lam * (xp - xr) - yp) % int(Pcurve)
    return (xr, yr)

def ECMultiply(xs, ys, Scalar): # Double & add. EC Multiplication, not true multiplication.
    if Scalar == 0 or Scalar >= N:
        raise Exception("Invalid Scalar/Private Key")
    ScalarBin = str(bin(Scalar))[2:]
    Qx, Qy = xs, ys
    for i in range (1, len(ScalarBin)): # This is invented EC multiplication.
        Qx, Qy = ECDouble(Qx, Qy) # print "DUB", Qx; print.
        if ScalarBin[i] == "1":
            Qx, Qy = ECAdd(Qx, Qy, xs, ys) # print "ADD", Qx; print.
    return (Qx, Qy)

xPublicKey, yPublicKey = ECMultiply(Gx, Gy, PrivKey)
publicKey = xPublicKey, yPublicKey

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
print ("   " + "04" + hex(publicKey[0])[2:].zfill(64).upper() + hex(publicKey[1])[2:].zfill(64).upper())
print ()
print ("--------------------------------------------------------------------------------------------------------------------------------------------")
print ()
if publicKey[1] % 2 == 1: # If the Y coordinate of the Public Key is odd.
    prefix = "'03'"
else: # If the Y coordinate of the Public Key is even.
    prefix = "'02'"
print ("  'Public Key' derived from 'Private Key' using 'secp256k1 elliptic curve' (compressed, 66 characters hexadecimal [0-9A-F]):")
print ()
print ("        [prefix = " + prefix + "] + [32 bytes of X coordinate]")
print ()
if publicKey[1] % 2 == 1: # If the Y coordinate of the Public Key is odd.
    print ("   " + "03" + hex(publicKey[0])[2:].zfill(64).upper())
else: # If the Y coordinate of the Public Key is even.
    print ("   " + "02" + hex(publicKey[0])[2:].zfill(64).upper())
print ()
print ("--------------------------------------------------------------------------------------------------------------------------------------------")
print ()
print ("  Signature Generation:")
xRandSignPoint, yRandSignPoint = ECMultiply(Gx, Gy, RandNum)
r = xRandSignPoint % N
print ()
print ("   r =", hex(r)[2:].zfill(64).upper())
s = ((HashedMessage + r * PrivKey) * (ModInv(RandNum, N))) % N
print ("   s =", hex(s)[2:].zfill(64).upper())
print ()
print ("--------------------------------------------------------------------------------------------------------------------------------------------")
print ()
print ("  Signature Verification:")
print ()
w = ModInv(s, N)
xu1, yu1 = ECMultiply(Gx, Gy, (HashedMessage * w) % N)
xu2, yu2 = ECMultiply(xPublicKey, yPublicKey, (r * w) % N)
x, y = ECAdd(xu1, yu1, xu2, yu2)
print ("  ", r==x)
print ()
print ("--------------------------------------------------------------------------------------------------------------------------------------------")
print ()
