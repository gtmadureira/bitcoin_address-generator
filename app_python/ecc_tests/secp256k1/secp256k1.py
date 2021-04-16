# Super simple elliptic curve presentation with signature generation and verification.
# For educational purposes only.
# Works on Python 3.6.13 or higher.
# Source: https://github.com/gtmadureira/bitcoin_address-generator/blob/main/app_python/ecc_tests/secp256k1/secp256k1.py

import os
import sys
import base64
from randpass import passgen
import argon2 # Need to install the Argon2 package '$ pip install argon2-cffi'.

# Checking the type of Operating System.
if sys.platform == "linux" or sys.platform == "linux2" or sys.platform == "darwin":
    def clear(): os.system('clear') # On Linux/OS X System.
elif sys.platform == "win32":
    def clear(): os.system('cls') # On Windows System.

clear()
print()
print(' {}{}{}{}'.format('\033[94m\033[5m', '[➭]', '\033[0m', ' Wait, the program is running ...'))

Password_Size = 1024 # Password size.
Salt_Size = 72 # Salt size.
RandPassPvK = passgen(Password_Size) # Generates a random password for the private key creation process.
RandPassNum = passgen(Password_Size) # Generates a random password for the process of creating a number.
RandSaltPvK = passgen(Salt_Size)
RandSaltNum = passgen(Salt_Size)
RandSaltMsg = passgen(Salt_Size)

# Hashing 'RandPassPvK' with Argon2(Argon2id mode) algorithm for Random Private Key.
HashingPassword = argon2.low_level.hash_secret(RandPassPvK.encode('utf-8'), RandSaltPvK.encode('utf-8'),
                                                time_cost = 20, memory_cost = 1048576, parallelism = 10,
                                                hash_len = 32, type = argon2.low_level.Type.ID)
HashingPassword = HashingPassword.decode("utf-8")
HashedPassword = base64.b64decode(HashingPassword[-43:] + '=').hex() # With custom cost settings.
RandPrivKey = int("0x" + HashedPassword, 16) # Random hashed Private Key at hex.

# Hashing 'RandPassNum' with Argon2(Argon2id mode) algorithm for Random Number.
HashingNumber = argon2.low_level.hash_secret(RandPassNum.encode('utf-8'), RandSaltNum.encode('utf-8'),
                                                time_cost = 20, memory_cost = 1048576, parallelism = 10,
                                                hash_len = 32, type = argon2.low_level.Type.ID)
HashingNumber = HashingNumber.decode("utf-8")
HashedNumber = base64.b64decode(HashingNumber[-43:] + '=').hex() # With custom cost settings.
RandNum = int("0x" + HashedNumber, 16) # Random hashed Number at hex.

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
        msg_tx.append('\t' + line + '\n')
temp_file = open("__temp__", "w")
temp_file.writelines(msg_tx)
temp_file = open("__temp__")
Message = temp_file.read()
temp_file.close()
os.remove("__temp__")
clear()
print(' {}{}{}{}'.format('\033[94m\033[5m', '[➭]', '\033[0m', ' Almost finished! Wait, the program is running ...'))
HashingMessage = argon2.low_level.hash_secret(Message.encode('utf-8'), RandSaltMsg.encode('utf-8'),
                                                time_cost = 20, memory_cost = 1048576, parallelism = 10,
                                                hash_len = 32, type = argon2.low_level.Type.ID)
HashingMessage = HashingMessage.decode("utf-8")
HashedMessage = base64.b64decode(HashingMessage[-43:] + '=').hex() # With custom cost settings.
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

ph = argon2.PasswordHasher()

try:
    if ph.verify(HashingPassword, RandPassPvK) == True:
        PKHashResult = '    {}{}{}'.format('\033[92m', '[✔] Good Hash', '\033[0m')
        RandPrivKeyResult = '    {}{}{}'.format('\033[96m', hex(RandPrivKey)[2:].zfill(64).upper(), '\033[0m')
        PubKeyResult = '    {}{}{}'.format('\033[96m', '04' + hex(publicKey[0])[2:].zfill(64).upper() + hex(publicKey[1])[2:].zfill(64).upper(), '\033[0m')
        if publicKey[1] % 2 == 1: # If the Y coordinate of the Public Key is odd.
            prefix = "'03'"
            UncompPubKeyResult = '    {}{}{}'.format('\033[96m', '03' + hex(publicKey[0])[2:].zfill(64).upper(), '\033[0m')
        else: # If the Y coordinate of the Public Key is even.
            prefix = "'02'"
            UncompPubKeyResult = '    {}{}{}'.format('\033[96m', '02' + hex(publicKey[0])[2:].zfill(64).upper(), '\033[0m')
        xRandSignPoint, yRandSignPoint = ECMultiply(Gx, Gy, RandNum)
        r = xRandSignPoint % N
        s = ((HashedMSG + r * RandPrivKey) * (ModInv(RandNum, N))) % N
        Rr = '    {}{}{}'.format('\033[96m', 'r = ' + hex(r)[2:].zfill(64).upper(), '\033[0m')
        Ss = '    {}{}{}'.format('\033[96m', 's = ' + hex(s)[2:].zfill(64).upper(), '\033[0m')
        w = ModInv(s, N)
        xu1, yu1 = ECMultiply(Gx, Gy, (HashedMSG * w) % N)
        xu2, yu2 = ECMultiply(xPublicKey, yPublicKey, (r * w) % N)
        x, y = ECAdd(xu1, yu1, xu2, yu2)
        if r==x:
            rx = '    {}{}{}'.format('\033[92m', '[✔] Good signature', '\033[0m')
        else:
            rx = '    {}{}{}'.format('\033[95m', '[X] Bad signature', '\033[0m')
            
except Exception:
    PKHashResult = '    {}{}{}'.format('\033[95m', '[X] Bad Hash', '\033[0m')
    RandPrivKeyResult = '    {}{}{}'.format('\033[95m', '[X] Bad Private Key caused by Bad Hash', '\033[0m')
    PubKeyResult = '    {}{}{}'.format('\033[95m', '[X] Bad Public Key caused by Bad Hash', '\033[0m')
    prefix = "'NONE'"
    Rr = '    {}{}{}'.format('\033[95m', '[X] Bad Value caused by Bad Hash', '\033[0m')
    Ss = '    {}{}{}'.format('\033[95m', '[X] Bad Value caused by Bad Hash', '\033[0m')
    rx = '    {}{}{}'.format('\033[95m', '[X] Bad signature caused by Bad Hash', '\033[0m')
    
try:
    if ph.verify(HashingNumber, RandPassNum) == True:
        NumHashResult = '    {}{}{}'.format('\033[92m', '[✔] Good Hash', '\033[0m')
        RandNumResult = '    {}{}{}'.format('\033[96m', hex(RandNum)[2:].zfill(64).upper(), '\033[0m')
        
except Exception:
    NumHashResult = '    {}{}{}'.format('\033[95m', '[X] Bad Hash', '\033[0m')
    RandNumResult = '    {}{}{}'.format('\033[95m', '[X] Bad Number caused by Bad Hash', '\033[0m')
    
try:
    if ph.verify(HashingMessage, Message) == True:
        MsgHashResult = '    {}{}{}'.format('\033[92m', '[✔] Good Hash', '\033[0m')
        MsgHashedResult = '    {}{}{}'.format('\033[96m', hex(HashedMSG)[2:].zfill(64).upper(), '\033[0m')
        
except Exception:
    MsgHashResult = '    {}{}{}'.format('\033[95m', '[X] Bad Hash', '\033[0m')
    MsgHashedResult = '    {}{}{}'.format('\033[95m', '[X] Bad Hashed Message caused by Bad Hash', '\033[0m')

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
print()
print("  Used Salt:")
print()
print('    {}{}{}'.format('\033[96m', RandSaltPvK, '\033[0m'))
print()
print()
print("  Argon2 Output in Encoded Form:")
print()
print('    {}{}{}'.format('\033[96m', HashingPassword[0:128], '\033[0m'))
print('    {}{}{}'.format('\033[96m', HashingPassword[128:175], '\033[0m'))
print()
print(PKHashResult)
print()
print()
print("  'Private Key' derived from Password above (64 characters hexadecimal [0-9A-F], hashed by Argon2\\ **id**):")
print()
print(RandPrivKeyResult)
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
print()
print("  Used Salt:")
print()
print('    {}{}{}'.format('\033[96m', RandSaltNum, '\033[0m'))
print()
print()
print("  Argon2 Output in Encoded Form:")
print()
print('    {}{}{}'.format('\033[96m', HashingNumber[0:128], '\033[0m'))
print('    {}{}{}'.format('\033[96m', HashingNumber[128:175], '\033[0m'))
print()
print(NumHashResult)
print()
print()
print("  'Number' used in the signature calculations, derived from last Password above (64 characters hexadecimal [0-9A-F], hashed by Argon2\\ **id**):")
print()
print(RandNumResult)
print()
print('{}{}{}'.format('\033[91m', '--------------------------------------------------------------------------------------------------------------------------------------------------------------', '\033[0m'))
print()
print("  'Public Key' derived from 'Private Key' using 'secp256k1 elliptic curve' (uncompressed, 130 characters hexadecimal [0-9A-F]):")
print()
print('        {}{}{}'.format('\033[93m', "[prefix = '04'] + [32 bytes of X coordinate] + [32 bytes of Y coordinate]", '\033[0m'))
print()
print(PubKeyResult)
print()
print()
print("  'Public Key' derived from 'Private Key' using 'secp256k1 elliptic curve' (compressed, 66 characters hexadecimal [0-9A-F]):")
print()
print('        {}{}{}'.format('\033[93m', '[prefix =' + prefix + '] + [32 bytes of X coordinate]', '\033[0m'))
print()
print(UncompPubKeyResult)
print()
print('{}{}{}'.format('\033[91m', '--------------------------------------------------------------------------------------------------------------------------------------------------------------', '\033[0m'))
print()
print("  'Message or Transaction':")
print()
print('{}{}{}'.format('\033[96m', Message, '\033[0m'))
print()
print()
print("  Used Salt:")
print()
print('    {}{}{}'.format('\033[96m', RandSaltMsg, '\033[0m'))
print()
print()
print("  Argon2 Output in Encoded Form:")
print()
print('    {}{}{}'.format('\033[96m', HashingMessage[0:128], '\033[0m'))
print('    {}{}{}'.format('\033[96m', HashingMessage[128:175], '\033[0m'))
print()
print(MsgHashResult)
print()
print()
print("  'Hash' of Message/Transaction, derived from last pass above (64 characters hexadecimal [0-9A-F], hashed by Argon2\\ **id**):")
print()
print(MsgHashedResult)
print()
print('{}{}{}'.format('\033[91m', '--------------------------------------------------------------------------------------------------------------------------------------------------------------', '\033[0m'))
print()
print("  Signature Generation:")
print()
print(Rr)
print(Ss)
print()
print('{}{}{}'.format('\033[91m', '--------------------------------------------------------------------------------------------------------------------------------------------------------------', '\033[0m'))
print()
print("  Signature Verification:")
print()
print(rx)
print()
print('{}{}{}'.format('\033[91m', '--------------------------------------------------------------------------------------------------------------------------------------------------------------', '\033[0m'))
print()
print(' {}{}{}{}'.format('\033[92m\033[5m', '[✔]', '\033[0m', ' Finished!'))
print()
