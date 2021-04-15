# Super simple elliptic curve presentation with signature generation and verification.
# For educational purposes only.
# Works on Python 3.6.13 or higher.
# Source: https://github.com/gtmadureira/bitcoin_address-generator/blob/main/app_python/ecc_tests/secp256k1/secp256k1.py

import os
import sys
import base64
from randpass import passgen
from argon2 import PasswordHasher # Need to install the Argon2 package '$ pip install argon2-cffi'

# Checking the type of Operating System.
if sys.platform == "linux" or sys.platform == "linux2" or sys.platform == "darwin":
    def clear(): os.system('clear') # On Linux/OS X System.
elif sys.platform == "win32":
    def clear(): os.system('cls') # On Windows System.

clear()
print()
print(' {}{}{}{}'.format('\033[94m\033[5m', '[➭]', '\033[0m', ' Wait, the program is running ...'))

Password_Size = 1024 # Password size.
RandPassPvK = passgen(Password_Size) # Generates a Random Password.
RandPassNum = passgen(Password_Size)

# Argon2(Argon2id mode) hashing algorithm configuration.
# ph = PasswordHasher(hash_len=32, salt_len=32) # With standard cost settings.
ph = PasswordHasher(time_cost=20, memory_cost=1048576, parallelism=10, hash_len=32, salt_len=32) # With custom cost settings.

# Hashing 'RandPassPvK' with Argon2(Argon2id mode) algorithm for Random Private Key.
HashingPassword = ph.hash(RandPassPvK)
# HashedPassword = base64.b64decode(HashingPassword[76:] + '=').hex() # With standard cost settings.
HashedPassword = base64.b64decode(HashingPassword[79:] + '=').hex() # With custom cost settings.
RandPrivKey = int("0x" + HashedPassword, 16) # Random Private Key at hex.

# Hashing 'RandPassNum' with Argon2(Argon2id mode) algorithm for Random Number.
HashingNumber = ph.hash(RandPassNum)
# HashedNumber = base64.b64decode(HashingNumber[76:] + '=').hex() # With standard cost settings.
HashedNumber = base64.b64decode(HashingNumber[79:] + '=').hex() # With custom cost settings.
RandNum = int("0x" + HashedNumber, 16) # Random Number at hex.

# Hashing 'Message' with Argon2(Argon2id mode) algorithm.
clear()
print()
print(' {}{}{}{}'.format('\033[94m\033[5m', '[➭]', '\033[0m', ' Please! Enter information, like any transaction or message:'))
print('      {}{}{}{}{}'.format("(to end data entry, on a new line type '", '\033[93m\033[5m', ':wq', '\033[0m', "' and press Enter)"))
print()
msg_tx = []
while True:
    line = input()
    if line == ":wq":
        break
    else:
        msg_tx.append('\t' + line)
Message = '\n'.join(msg_tx)
clear()
print(' {}{}{}{}'.format('\033[94m\033[5m', '[➭]', '\033[0m', ' Almost finished! Wait, the program is running ...'))
HashingMessage = ph.hash(Message)
# HashedMessage = base64.b64decode(HashingMessage[76:] + '=').hex() # With standard cost settings.
HashedMessage = base64.b64decode(HashingMessage[79:] + '=').hex() # With custom cost settings.
HashedMSG = int("0x" + HashedMessage, 16) # The hash of your Message/transaction at hex.

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

xPublicKey, yPublicKey = ECMultiply(Gx, Gy, RandPrivKey)
publicKey = xPublicKey, yPublicKey

clear()

print()
print('{}{}{}'.format('\033[91m', '--------------------------------------------------------------------------------------------------------------------------------------------------------------', '\033[0m'))
print()
print("  'Password' to derive the Private Key, currently set with '" + str(Password_Size) + "' characters:")
print()
print('    {}{}{}'.format('\033[96m', RandPassPvK[0:128], '\033[0m'))
print('    {}{}{}'.format('\033[96m', RandPassPvK[128:256], '\033[0m'))
print('    {}{}{}'.format('\033[96m', RandPassPvK[256:384], '\033[0m'))
print('    {}{}{}'.format('\033[96m', RandPassPvK[384:512], '\033[0m'))
print('    {}{}{}'.format('\033[96m', RandPassPvK[512:640], '\033[0m'))
print('    {}{}{}'.format('\033[96m', RandPassPvK[640:768], '\033[0m'))
print('    {}{}{}'.format('\033[96m', RandPassPvK[768:896], '\033[0m'))
print('    {}{}{}'.format('\033[96m', RandPassPvK[896:1024], '\033[0m'))
print()
print('{}{}{}'.format('\033[91m', '--------------------------------------------------------------------------------------------------------------------------------------------------------------', '\033[0m'))
print()
print("  'Private Key' derived from Password above (64 characters hexadecimal [0-9A-F], hashed by Argon2\\ **id**):")
print()
print('    {}{}{}'.format('\033[96m', hex(RandPrivKey)[2:].zfill(64).upper(), '\033[0m'))
print()
print('{}{}{}'.format('\033[91m', '--------------------------------------------------------------------------------------------------------------------------------------------------------------', '\033[0m'))
print()
print("  'Another Password', but now to derive the hexadecimal Number used in the signature calculations, currently set with '" + str(Password_Size) + "' characters:")
print()
print('    {}{}{}'.format('\033[96m', RandPassNum[0:128], '\033[0m'))
print('    {}{}{}'.format('\033[96m', RandPassNum[128:256], '\033[0m'))
print('    {}{}{}'.format('\033[96m', RandPassNum[256:384], '\033[0m'))
print('    {}{}{}'.format('\033[96m', RandPassNum[384:512], '\033[0m'))
print('    {}{}{}'.format('\033[96m', RandPassNum[512:640], '\033[0m'))
print('    {}{}{}'.format('\033[96m', RandPassNum[640:768], '\033[0m'))
print('    {}{}{}'.format('\033[96m', RandPassNum[768:896], '\033[0m'))
print('    {}{}{}'.format('\033[96m', RandPassNum[896:1024], '\033[0m'))
print()
print('{}{}{}'.format('\033[91m', '--------------------------------------------------------------------------------------------------------------------------------------------------------------', '\033[0m'))
print()
print("  'Number' used in the signature calculations, derived from last Password above (64 characters hexadecimal [0-9A-F], hashed by Argon2\\ **id**):")
print()
print('    {}{}{}'.format('\033[96m', hex(RandNum)[2:].zfill(64).upper(), '\033[0m'))
print()
print('{}{}{}'.format('\033[91m', '--------------------------------------------------------------------------------------------------------------------------------------------------------------', '\033[0m'))
print()
print("  'Public Key' derived from 'Private Key' using 'secp256k1 elliptic curve' (uncompressed, 130 characters hexadecimal [0-9A-F]):")
print()
print('        {}{}{}'.format('\033[93m', "[prefix = '04'] + [32 bytes of X coordinate] + [32 bytes of Y coordinate]", '\033[0m'))
print()
print('    {}{}{}'.format('\033[96m', '04' + hex(publicKey[0])[2:].zfill(64).upper() + hex(publicKey[1])[2:].zfill(64).upper(), '\033[0m'))
print()
print('{}{}{}'.format('\033[91m', '--------------------------------------------------------------------------------------------------------------------------------------------------------------', '\033[0m'))
print()
print("  'Public Key' derived from 'Private Key' using 'secp256k1 elliptic curve' (compressed, 66 characters hexadecimal [0-9A-F]):")
print()
if publicKey[1] % 2 == 1: # If the Y coordinate of the Public Key is odd.
    prefix = "'03'"
else: # If the Y coordinate of the Public Key is even.
    prefix = "'02'"
print('        {}{}{}'.format('\033[93m', '[prefix =' + prefix + '] + [32 bytes of X coordinate]', '\033[0m'))
print()
if publicKey[1] % 2 == 1: # If the Y coordinate of the Public Key is odd.
    print('    {}{}{}'.format('\033[96m', '03' + hex(publicKey[0])[2:].zfill(64).upper(), '\033[0m'))
else: # If the Y coordinate of the Public Key is even.
    print('    {}{}{}'.format('\033[96m', '02' + hex(publicKey[0])[2:].zfill(64).upper(), '\033[0m'))
print()
print('{}{}{}'.format('\033[91m', '--------------------------------------------------------------------------------------------------------------------------------------------------------------', '\033[0m'))
print()
print("  'Message or Transaction':")
print()
print(Message)
print()
print('{}{}{}'.format('\033[91m', '--------------------------------------------------------------------------------------------------------------------------------------------------------------', '\033[0m'))
print()
print("  Signature Generation:")
print()
xRandSignPoint, yRandSignPoint = ECMultiply(Gx, Gy, RandNum)
r = xRandSignPoint % N
print('    {}{}{}'.format('\033[96m', 'r = ' + hex(r)[2:].zfill(64).upper(), '\033[0m'))
s = ((HashedMSG + r * RandPrivKey) * (ModInv(RandNum, N))) % N
print('    {}{}{}'.format('\033[96m', 's = ' + hex(s)[2:].zfill(64).upper(), '\033[0m'))
print()
print('{}{}{}'.format('\033[91m', '--------------------------------------------------------------------------------------------------------------------------------------------------------------', '\033[0m'))
print()
print("  Signature Verification:")
print()
w = ModInv(s, N)
xu1, yu1 = ECMultiply(Gx, Gy, (HashedMSG * w) % N)
xu2, yu2 = ECMultiply(xPublicKey, yPublicKey, (r * w) % N)
x, y = ECAdd(xu1, yu1, xu2, yu2)
if r==x:
    print('    {}{}{}'.format('\033[92m', '[✔] Good signature', '\033[0m'))
else:
    print('    {}{}{}'.format('\033[95m', '[X] Bad signature', '\033[0m'))
print()
print('{}{}{}'.format('\033[91m', '--------------------------------------------------------------------------------------------------------------------------------------------------------------', '\033[0m'))
print()
print(' {}{}{}{}'.format('\033[92m\033[5m', '[✔]', '\033[0m', ' Finished!'))
print()
