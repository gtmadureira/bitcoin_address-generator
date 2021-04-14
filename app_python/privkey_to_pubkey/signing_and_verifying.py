# Super simple Elliptic Curve Presentation.
# For educational purposes only.
# Works on Python 3.6.13 or higher.
# Source: https://github.com/gtmadureira/bitcoin_address-generator/blob/main/app_python/privkey_to_pubkey/secp256k1.py

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

password_size = 1024 # Password length.
password = randpass.passgen(password_size) # Generates a Random Password.

# Hashing password with SHA3-256 algorithm.
hashedPassword = hashlib.sha3_256()
hashedPassword.update(password.encode())

privKey = int("0x" + hashedPassword.hexdigest(), 16) # Random Private Key at hex_value.

randNum = randpass.numgen(64) # replace with a truly random number.

message = "O Rato roeu a roupa do Rei de Roma" # The message/transaction.
messageToHash = hashlib.sha3_256()
messageToHash.update(message.encode())
hashedMessage = int("0x" + messageToHash.hexdigest(), 16) # The hash of your message/transaction.

# secp256k1 domain parameters.
Pcurve = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F # The proven prime.
Acurve = 0x0000000000000000000000000000000000000000000000000000000000000000 # These two defines the elliptic curve.
Bcurve = 0x0000000000000000000000000000000000000000000000000000000000000007 #   y^2 = x^3 + int(Acurve) * x + int(Bcurve).
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
GPoint = (int(Gx), int(Gy)) # This is our generator point.
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 # Number of points in the field.

def modinv(a, n = int(Pcurve)): # Extended Euclidean Algorithm/'division' in elliptic curves.
    lm, hm = 1, 0
    low, high = a % n, n
    while low > 1:
        ratio = high // low
        nm, new = hm - lm * ratio, high - low * ratio
        lm, low, hm, high = nm, new, lm, low
    return lm % n

def ECadd(xp, yp, xq, yq): # Not true addition, invented for EC. It adds Point-P with Point-Q.
    m = ((yq - yp) * modinv(xq - xp, int(Pcurve)) % int(Pcurve))
    xr = (m * m - xp - xq) % int(Pcurve)
    yr = (m * (xp - xr) - yp) % int(Pcurve)
    return (xr, yr)

def ECdouble(xp, yp): # EC point doubling,  invented for EC. It doubles Point-P.
    LamNumer = 3 * xp * xp + int(Acurve)
    LamDenom = 2 * yp
    Lam = (LamNumer * modinv(LamDenom, int(Pcurve))) % int(Pcurve)
    xr = (Lam * Lam - 2 * xp) % int(Pcurve)
    yr = (Lam * (xp - xr) - yp) % int(Pcurve)
    return (xr, yr)

def EccMultiply(xs, ys, Scalar): # Double & add. EC Multiplication, Not true multiplication.
    if Scalar == 0 or Scalar >= N:
        raise Exception("Invalid Scalar/Private Key")
    ScalarBin = str(bin(Scalar))[2:]
    Qx, Qy = xs, ys
    for i in range (1, len(ScalarBin)): # This is invented EC multiplication.
        Qx, Qy = ECdouble(Qx, Qy) # print "DUB", Qx; print.
        if ScalarBin[i] == "1":
            Qx, Qy = ECadd(Qx, Qy, xs, ys) # print "ADD", Qx; print.
    return (Qx, Qy)

xPublicKey, yPublicKey = EccMultiply(Gx, Gy, privKey)
publicKey = xPublicKey, yPublicKey

print()
print("--------------------------------------------------------------------------------------------------------------------------------------------")
print()
print("  'Random Password' currently set with '" + str(password_size) + "' characters:")
print()
print ("   " + password[0:128])
print ("   " + password[128:256])
print ("   " + password[256:384])
print ("   " + password[384:512])
print ("   " + password[512:640])
print ("   " + password[640:768])
print ("   " + password[768:896])
print ("   " + password[896:1024])
print()
print("--------------------------------------------------------------------------------------------------------------------------------------------")
print()
print ("  'Private Key' derived from Hashed 'Random Password' (64 characters hexadecimal [0-9A-F], hashed by SHA3-256):")
print()
print ("   " + str(hex(privKey)[2:]).zfill(32).upper())
print()
print("--------------------------------------------------------------------------------------------------------------------------------------------")
print()
print ("  'Public Key' derived from 'Private Key' using 'secp256k1 elliptic curve' (uncompressed, 130 characters hexadecimal [0-9A-F])")
print ("  [prefix = '04'] + [32 bytes of X coordinate] + [32 bytes of Y coordinate]:")
print()
print ("   " + "04" + str(hex(publicKey[0])[2:]).zfill(64).upper() + str(hex(publicKey[1])[2:]).zfill(64).upper())
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
    print ("   " + "03" + str(hex(publicKey[0])[2:]).zfill(64).upper())
else: # If the Y coordinate of the Public Key is even.
    print ("   " + "02" + str(hex(publicKey[0])[2:]).zfill(64).upper())
print()
print("--------------------------------------------------------------------------------------------------------------------------------------------")
print()
print ("  Signature Generation:")
xRandSignPoint, yRandSignPoint = EccMultiply(Gx, Gy, randNum)
r = xRandSignPoint % N
print()
print ("   r =", str(hex(r)[2:]).upper())
s = ((hashedMessage + r * privKey) * (modinv(randNum, N))) % N
print ("   s =", str(hex(s)[2:]).upper())
print()
print("--------------------------------------------------------------------------------------------------------------------------------------------")
print()
print ("  Signature Verification:")
print()
w = modinv(s, N)
xu1, yu1 = EccMultiply(Gx, Gy, (hashedMessage * w) % N)
xu2, yu2 = EccMultiply(xPublicKey, yPublicKey, (r * w) % N)
x, y = ECadd(xu1, yu1, xu2, yu2)
print ("  ", r==x)
print()
print("--------------------------------------------------------------------------------------------------------------------------------------------")
print()
