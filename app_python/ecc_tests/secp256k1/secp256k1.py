# secp256k1 elliptic curve presentation with signature generation and verification.
# For educational purposes only.
# Works on Python 3.6.13 or higher.
# Source: https://github.com/gtmadureira/bitcoin_address-generator/blob/main/app_python/ecc_tests/secp256k1/secp256k1.py

import os
import sys
import random
import array
import base64
import hashlib
import argon2 # Need to install the Argon2 package ' $ pip install argon2-cffi '.

# Checking the type of operating system.
if sys.platform == "linux" or sys.platform == "linux2" or sys.platform == "darwin":
    def clear(): os.system('clear') # On Linux/OS X system.
elif sys.platform == "win32":
    def clear(): os.system('cls') # On Windows system.

clear()

# Password generator function.
def passgen(length: int) -> str:
    """ Return a random password. """

    # Maximum length of password needed.
    MAX_LEN = length

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

    # Combine the character randomly selected above,
    # at this stage, the password contains only 4 characters.
    temp_pass = rand_digit + rand_upper + rand_lower + rand_symbol

    # Now that we are sure we have at least one character from each
    # set of characters, we fill the rest of the password length by
    # selecting randomly from the combined list of character above.
    for x in range(MAX_LEN - 4):
        temp_pass = temp_pass + random.choice(COMBINED_LIST)

    # Convert temporary password into array and shuffle to
    # prevent it from having a consistent pattern
    # where the beginning of the password is predictable.
        temp_pass_list = array.array('u', temp_pass)
        random.shuffle(temp_pass_list)

    # Traverse the temporary password array and append the chars
    # to form the password.
    pswd = ""
    for x in temp_pass_list:
        pswd = pswd + x
        
    return pswd

print()
print(' {}{}{}{}'.format('\033[94m\033[5m', '[➭]', '\033[0m', ' Wait, the program is running ...'))

Password_Size = 1024 # Password size.
Salt_Size = 128 # Salt size.
RandPassPvK = passgen(Password_Size) # Generates a random password for the private key creation process.
RandPassNum = passgen(Password_Size) # Generates a random password for the process of creating a number used in signature calculations.
RandSaltPvK = passgen(Salt_Size) # Generates a random salt for the process of hashing password for private key.
RandSaltNum = passgen(Salt_Size) # Generates a random salt for the process of hashing password for number used in signature calculations.

# Configuration of the Argon2 hash function.
timeCost = 4 # 2 is the default value.
memoryCost = 1048576 # 102400 is the default value.
paraLLelism = 20 # 8 is the default value.

# Hashing 'RandPassPvK' with Argon2(*id* version) algorithm, to create a random private key.
HashingPassword = argon2.low_level.hash_secret(RandPassPvK.encode('utf-8'), RandSaltPvK.encode('utf-8'),
                                                time_cost = timeCost, memory_cost = memoryCost, parallelism = paraLLelism,
                                                hash_len = 32, type = argon2.low_level.Type.ID)
HashingPassword = HashingPassword.decode("utf-8")
HashedPassword = base64.b64decode(HashingPassword[-43:] + '=').hex()
RandPrivKey = int("0x" + HashedPassword, 16) # Random hashed private key, created in hexadecimal format.

# Hashing 'RandPassNum' with Argon2(*id* version) algorithm, to create a random number.
HashingNumber = argon2.low_level.hash_secret(RandPassNum.encode('utf-8'), RandSaltNum.encode('utf-8'),
                                                time_cost = timeCost, memory_cost = memoryCost, parallelism = paraLLelism,
                                                hash_len = 32, type = argon2.low_level.Type.ID)
HashingNumber = HashingNumber.decode("utf-8")
HashedNumber = base64.b64decode(HashingNumber[-43:] + '=').hex()
RandNum = int("0x" + HashedNumber, 16) # Random hashed number, created in hexadecimal format.

clear()

# Getting the messages/transactions through stdin.
print()
print(' {}{}{}{}'.format('\033[94m\033[5m', '[➭]', '\033[0m', ' Please! Enter information, like any transaction or message:'))
print('      {}{}{}{}{}'.format("(to end data entry, on a new line type '", '\033[93m\033[5m', ':wq', '\033[0m', "' and press Enter)"))
print()
msg_tx = ["\t[000001]:  -----BEGIN MESSAGE/TRANSACTION-----\n"]
msg_tx_file = ["[000001]:  -----BEGIN MESSAGE/TRANSACTION-----\n"]
linenumber = 2
while True:
    line = input()
    if line == ":wq":
        msg_tx.append("\t[" + str(linenumber).zfill(6) + "]:  ------END MESSAGE/TRANSACTION------")        
        msg_tx_file.append("[" + str(linenumber).zfill(6) + "]:  ------END MESSAGE/TRANSACTION------")
        break
    else:
        msg_tx.append("\t[" + str(linenumber).zfill(6) + "]:  " + line + "\n")
        msg_tx_file.append("[" + str(linenumber).zfill(6) + "]:  " + line + "\n")
        linenumber += 1
temp_file = open("__temp__", "w")
msg_file = open("__lastmsg__", "w")
temp_file.writelines(msg_tx)
msg_file.writelines(msg_tx_file)
temp_file = open("__temp__")
msg_file = open("__lastmsg__")
screenMessage = temp_file.read()
Message = msg_file.read()
temp_file.close()
msg_file.close()
os.remove("__temp__")
os.remove("__lastmsg__")
clear()

# Hashing 'Message' with SHA3-256 algorithm.
print()
print(' {}{}{}{}'.format('\033[94m\033[5m', '[➭]', '\033[0m', ' Almost finished! Wait, the program is running ...'))
HashingMessage = hashlib.sha3_256(Message.encode('utf-8')).hexdigest()
HashedMSG = int("0x" + HashingMessage, 16) # Hashed messages/transactions in hexadecimal format.

# secp256k1 domain parameters.
Pcurve = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F # The proven prime.
Acurve = 0x0000000000000000000000000000000000000000000000000000000000000000 # These two values defines the elliptic curve.
Bcurve = 0x0000000000000000000000000000000000000000000000000000000000000007 # y^2 = x^3 + Acurve * x + Bcurve.
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798 # This is the x coordinate of the generating point.
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8 # This is the y coordinate of the generating point.
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 # Number of points in the field.

def ModInv(a, n = Pcurve): # Extended euclidean algorithm/'division' in elliptic curves.
    lm, hm = 1, 0
    low, high = a % n, n
    while low > 1:
        ratio = high // low
        nm, new = hm - lm * ratio, high - low * ratio
        lm, low, hm, high = nm, new, lm, low
    return lm % n

def ECAdd(xp, yp, xq, yq): # Not true addition, invented for EC. It adds Point-P with Point-Q.
    m = ((yq - yp) * ModInv(xq - xp, Pcurve) % Pcurve)
    xr = (m * m - xp - xq) % Pcurve
    yr = (m * (xp - xr) - yp) % Pcurve
    return (xr, yr)

def ECDouble(xp, yp): # EC point doubling, invented for EC. It doubles Point-P.
    LamNumer = 3 * xp * xp + Acurve
    LamDenom = 2 * yp
    Lam = (LamNumer * ModInv(LamDenom, Pcurve)) % Pcurve
    xr = (Lam * Lam - 2 * xp) % Pcurve
    yr = (Lam * (xp - xr) - yp) % Pcurve
    return (xr, yr)

def ECMultiply(xs, ys, Scalar): # Double & Add. EC multiplication, not true multiplication.
    ScalarBin = str(bin(Scalar))[2:]
    Qx, Qy = xs, ys
    for i in range (1, len(ScalarBin)): # This is invented EC multiplication.
        Qx, Qy = ECDouble(Qx, Qy) # print "DUB", Qx; print.
        if ScalarBin[i] == "1":
            Qx, Qy = ECAdd(Qx, Qy, xs, ys) # print "ADD", Qx; print.
    return (Qx, Qy)

xPublicKey, yPublicKey = ECMultiply(Gx, Gy, RandPrivKey)
publicKey = xPublicKey, yPublicKey

# Starts the process of building and displaying (stdout) the results to the user.
ph = argon2.PasswordHasher()
finalResult = ' {}{}{}{}'.format('\033[92m\033[5m', '[✔]', '\033[0m', ' Finished!')

# If both Private Key and Number are good.
if RandPrivKey > 0 and RandPrivKey < N:
    if RandNum > 0 and  RandNum < N:
        try:
            if ph.verify(HashingPassword, RandPassPvK) == True:
                PKHashResult = '    {}{}{}'.format('\033[92m', '[✔] Good Hash', '\033[0m')
                RandPrivKeyResult = '    {}{}{}'.format('\033[96m', hex(RandPrivKey)[2:].zfill(64).upper(), '\033[0m')
                PubKeyResult = '    {}{}{}'.format('\033[96m', '04' + hex(publicKey[0])[2:].zfill(64).upper() + hex(publicKey[1])[2:].zfill(64).upper(), '\033[0m')
                if publicKey[1] % 2 == 1: # If the Y coordinate of the Public Key is odd.
                    prefix = "The Y coordinate is an odd value, so prefix = 03"
                    compPubKeyResult = '    {}{}{}'.format('\033[96m', '03' + hex(publicKey[0])[2:].zfill(64).upper(), '\033[0m')
                else: # If the Y coordinate of the Public Key is even.
                    prefix = "The Y coordinate is an even value, so prefix = 02"
                    compPubKeyResult = '    {}{}{}'.format('\033[96m', '02' + hex(publicKey[0])[2:].zfill(64).upper(), '\033[0m')
                
                # This creates the message/transaction signature.
                xRandSignPoint, yRandSignPoint = ECMultiply(Gx, Gy, RandNum)
                r = xRandSignPoint % N
                s = ((HashedMSG + r * RandPrivKey) * (ModInv(RandNum, N))) % N
                Rr = '    {}{}{}'.format('\033[96m', 'r = ' + hex(r)[2:].zfill(64).upper(), '\033[0m')
                Ss = '    {}{}{}'.format('\033[96m', 's = ' + hex(s)[2:].zfill(64).upper(), '\033[0m')
                
                # This verifies the signature of the message/transaction.
                w = ModInv(s, N)
                xu1, yu1 = ECMultiply(Gx, Gy, (HashedMSG * w) % N)
                xu2, yu2 = ECMultiply(xPublicKey, yPublicKey, (r * w) % N)
                x, y = ECAdd(xu1, yu1, xu2, yu2)
                if r==x:
                    sigResult = '    {}{}{}'.format('\033[92m', '[✔] Good signature', '\033[0m')
                else:
                    sigResult = '    {}{}{}'.format('\033[95m', '[X] Bad signature', '\033[0m')
                    
        except Exception:
            PKHashResult = '    {}{}{}'.format('\033[95m', '[X] Bad Hash', '\033[0m')
            RandPrivKeyResult = '    {}{}{}'.format('\033[95m', '[X] Bad Private Key caused by Bad Hash', '\033[0m')
            PubKeyResult = '    {}{}{}'.format('\033[95m', '[X] Bad Public Key caused by Bad Private Key Hash', '\033[0m')
            prefix = "'NONE'"
            compPubKeyResult = '    {}{}{}'.format('\033[95m', '[X] Bad Public Key caused by Bad Private Key Hash', '\033[0m')
            Rr = '    {}{}{}'.format('\033[95m', '[X] Bad Value caused by Bad Private Key Hash', '\033[0m')
            Ss = '    {}{}{}'.format('\033[95m', '[X] Bad Value caused by Bad Private Key Hash', '\033[0m')
            sigResult = '    {}{}{}'.format('\033[95m', '[X] Bad signature caused by Bad Private Key Hash', '\033[0m')
            finalResult = ' {}{}{}{}'.format('\033[95m\033[5m', '[X]', '\033[0m', ' Error!')
            
        try:
            if ph.verify(HashingNumber, RandPassNum) == True:
                NumHashResult = '    {}{}{}'.format('\033[92m', '[✔] Good Hash', '\033[0m')
                RandNumResult = '    {}{}{}'.format('\033[96m', hex(RandNum)[2:].zfill(64).upper(), '\033[0m')
                
        except Exception:
            NumHashResult = '    {}{}{}'.format('\033[95m', '[X] Bad Hash', '\033[0m')
            RandNumResult = '    {}{}{}'.format('\033[95m', '[X] Bad Number caused by Bad Hash', '\033[0m')
            Rr = '    {}{}{}'.format('\033[95m', '[X] Bad Value caused by Bad Number Hash', '\033[0m')
            Ss = '    {}{}{}'.format('\033[95m', '[X] Bad Value caused by Bad Number Hash', '\033[0m')
            sigResult = '    {}{}{}'.format('\033[95m', '[X] Bad signature caused by Bad Number Hash', '\033[0m')
            finalResult = ' {}{}{}{}'.format('\033[95m\033[5m', '[X]', '\033[0m', ' Error!')
            
        if hashlib.sha3_256(Message.encode('utf-8')).hexdigest() == HashingMessage:
            MsgHashResult = '    {}{}{}'.format('\033[92m', '[✔] Good Hash', '\033[0m')
            MsgHashedResult = '    {}{}{}'.format('\033[96m', hex(HashedMSG)[2:].zfill(64).upper(), '\033[0m')
                
        else:
            MsgHashResult = '    {}{}{}'.format('\033[95m', '[X] Bad Hash', '\033[0m')
            MsgHashedResult = '    {}{}{}'.format('\033[95m', '[X] Bad Hashed Message caused by Bad Hash', '\033[0m')
            Rr = '    {}{}{}'.format('\033[95m', '[X] Bad Value caused by Bad Message/Transaction Hash', '\033[0m')
            Ss = '    {}{}{}'.format('\033[95m', '[X] Bad Value caused by Bad Message/Transaction Hash', '\033[0m')
            sigResult = '    {}{}{}'.format('\033[95m', '[X] Bad signature caused by Bad Message/Transaction Hash', '\033[0m')
            finalResult = ' {}{}{}{}'.format('\033[95m\033[5m', '[X]', '\033[0m', ' Error!')

# If Private Key is bad.
if RandPrivKey == 0 or RandPrivKey >= N:
    PKHashResult = '    {}{}{}'.format('\033[95m', '[X] Bad Hash', '\033[0m')
    RandPrivKeyResult = '    {}{}{}'.format('\033[95m', '[X] Bad Private Key caused by invalid escalation', '\033[0m')
    PubKeyResult = '    {}{}{}'.format('\033[95m', '[X] Bad Public Key caused by invalid escalation of Private Key', '\033[0m')
    prefix = "'NONE'"
    compPubKeyResult = '    {}{}{}'.format('\033[95m', '[X] Bad Public Key caused by invalid escalation of Private Key', '\033[0m')
    try:
        if ph.verify(HashingNumber, RandPassNum) == True:
            NumHashResult = '    {}{}{}'.format('\033[92m', '[✔] Good Hash', '\033[0m')
            RandNumResult = '    {}{}{}'.format('\033[96m', hex(RandNum)[2:].zfill(64).upper(), '\033[0m')
                
    except Exception:
        NumHashResult = '    {}{}{}'.format('\033[95m', '[X] Bad Hash', '\033[0m')
        RandNumResult = '    {}{}{}'.format('\033[95m', '[X] Bad Number caused by Bad Hash', '\033[0m')
    if hashlib.sha3_256(Message.encode('utf-8')).hexdigest() == HashingMessage:
        MsgHashResult = '    {}{}{}'.format('\033[92m', '[✔] Good Hash', '\033[0m')
        MsgHashedResult = '    {}{}{}'.format('\033[96m', hex(HashedMSG)[2:].zfill(64).upper(), '\033[0m')
            
    else:
        MsgHashResult = '    {}{}{}'.format('\033[95m', '[X] Bad Hash', '\033[0m')
        MsgHashedResult = '    {}{}{}'.format('\033[95m', '[X] Bad Hashed Message caused by Bad Hash', '\033[0m')    
    Rr = '    {}{}{}'.format('\033[95m', '[X] Bad Value caused by invalid escalation of Private Key', '\033[0m')
    Ss = '    {}{}{}'.format('\033[95m', '[X] Bad Value caused by invalid escalation of Private Key', '\033[0m')
    sigResult = '    {}{}{}'.format('\033[95m', '[X] Bad signature caused by invalid escalation of Private Key', '\033[0m')
    finalResult = ' {}{}{}{}'.format('\033[95m\033[5m', '[X]', '\033[0m', ' Error!')

# If Number is bad.
if RandNum == 0 or RandNum >= N:
    try:        
        if ph.verify(HashingPassword, RandPassPvK) == True:
            PKHashResult = '    {}{}{}'.format('\033[92m', '[✔] Good Hash', '\033[0m')
            RandPrivKeyResult = '    {}{}{}'.format('\033[96m', hex(RandPrivKey)[2:].zfill(64).upper(), '\033[0m')
            PubKeyResult = '    {}{}{}'.format('\033[96m', '04' + hex(publicKey[0])[2:].zfill(64).upper() + hex(publicKey[1])[2:].zfill(64).upper(), '\033[0m')
            if publicKey[1] % 2 == 1: # If the Y coordinate of the Public Key is odd.
                prefix = "The Y coordinate is an odd value, so prefix = 03"
                compPubKeyResult = '    {}{}{}'.format('\033[96m', '03' + hex(publicKey[0])[2:].zfill(64).upper(), '\033[0m')
            else: # If the Y coordinate of the Public Key is even.
                prefix = "The Y coordinate is an even value, so prefix = 02"
                compPubKeyResult = '    {}{}{}'.format('\033[96m', '02' + hex(publicKey[0])[2:].zfill(64).upper(), '\033[0m')
                    
    except Exception:
        PKHashResult = '    {}{}{}'.format('\033[95m', '[X] Bad Hash', '\033[0m')
        RandPrivKeyResult = '    {}{}{}'.format('\033[95m', '[X] Bad Private Key caused by Bad Hash', '\033[0m')
        PubKeyResult = '    {}{}{}'.format('\033[95m', '[X] Bad Public Key caused by Bad Hash', '\033[0m')
        prefix = "'NONE'"
        compPubKeyResult = '    {}{}{}'.format('\033[95m', '[X] Bad Public Key caused by Bad Hash', '\033[0m')
    if hashlib.sha3_256(Message.encode('utf-8')).hexdigest() == HashingMessage:
        MsgHashResult = '    {}{}{}'.format('\033[92m', '[✔] Good Hash', '\033[0m')
        MsgHashedResult = '    {}{}{}'.format('\033[96m', hex(HashedMSG)[2:].zfill(64).upper(), '\033[0m')
            
    else:
        MsgHashResult = '    {}{}{}'.format('\033[95m', '[X] Bad Hash', '\033[0m')
        MsgHashedResult = '    {}{}{}'.format('\033[95m', '[X] Bad Hashed Message caused by Bad Hash', '\033[0m')        
    NumHashResult = '    {}{}{}'.format('\033[95m', '[X] Bad Hash', '\033[0m')
    RandNumResult = '    {}{}{}'.format('\033[95m', '[X] Bad Number caused by invalid escalation', '\033[0m')
    Rr = '    {}{}{}'.format('\033[95m', '[X] Bad Value caused by invalid escalation of Number', '\033[0m')
    Ss = '    {}{}{}'.format('\033[95m', '[X] Bad Value caused by invalid escalation of Number', '\033[0m')
    sigResult = '    {}{}{}'.format('\033[95m', '[X] Bad signature caused by invalid escalation of Number', '\033[0m')
    finalResult = ' {}{}{}{}'.format('\033[95m\033[5m', '[X]', '\033[0m', ' Error!')

# If both Private Key and Number are bad.    
if RandPrivKey == 0 or RandPrivKey >= N:
    if RandNum == 0 or  RandNum >= N:
        PKHashResult = '    {}{}{}'.format('\033[95m', '[X] Bad Hash', '\033[0m')
        RandPrivKeyResult = '    {}{}{}'.format('\033[95m', '[X] Bad Private Key caused by invalid escalation', '\033[0m')
        PubKeyResult = '    {}{}{}'.format('\033[95m', '[X] Bad Public Key caused by invalid escalation of Private Key', '\033[0m')
        prefix = "'NONE'"
        compPubKeyResult = '    {}{}{}'.format('\033[95m', '[X] Bad Public Key caused by invalid escalation of Private Key', '\033[0m')
        NumHashResult = '    {}{}{}'.format('\033[95m', '[X] Bad Hash', '\033[0m')
        if hashlib.sha3_256(Message.encode('utf-8')).hexdigest() == HashingMessage:
            MsgHashResult = '    {}{}{}'.format('\033[92m', '[✔] Good Hash', '\033[0m')
            MsgHashedResult = '    {}{}{}'.format('\033[96m', hex(HashedMSG)[2:].zfill(64).upper(), '\033[0m')
                
        else:
            MsgHashResult = '    {}{}{}'.format('\033[95m', '[X] Bad Hash', '\033[0m')
            MsgHashedResult = '    {}{}{}'.format('\033[95m', '[X] Bad Hashed Message caused by Bad Hash', '\033[0m')
        RandNumResult = '    {}{}{}'.format('\033[95m', '[X] Bad Number caused by invalid escalation', '\033[0m')
        Rr = '    {}{}{}'.format('\033[95m', '[X] Bad Value caused by invalid escalation of Private Key and Number', '\033[0m')
        Ss = '    {}{}{}'.format('\033[95m', '[X] Bad Value caused by invalid escalation of Private Key and Number', '\033[0m')
        sigResult = '    {}{}{}'.format('\033[95m', '[X] Bad signature caused by invalid escalation of Private Key and Number', '\033[0m')
        finalResult = ' {}{}{}{}'.format('\033[95m\033[5m', '[X]', '\033[0m', ' Error!')

clear()

print()
print('{}{}{}'.format('\033[91m', '--------------------------------------------------------------------------------------------------------------------------------------------------------------', '\033[0m'))
print()
print("  Password to derive the Private Key, currently set with " + str(Password_Size) + " characters:")
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
print("  Salt used in the hashing function:")
print()
print('    {}{}{}'.format('\033[96m', RandSaltPvK, '\033[0m'))
print()
print()
print("  Output with the random password hash, in encoded format (hashed by Argon2*id* version):")
print()
print('    {}{}{}'.format('\033[96m', HashingPassword[0:128], '\033[0m'))
print('    {}{}{}'.format('\033[96m', HashingPassword[128:], '\033[0m'))
print()
print(PKHashResult)
print()
print()
print("  Private Key derived from the password hash above (64 hex digits [0-9A-F]):")
print()
print('        {}{}{}'.format('\033[93m', '[256 bits] [32 bytes] of length', '\033[0m'))
print()
print(RandPrivKeyResult)
print()
print('{}{}{}'.format('\033[91m', '--------------------------------------------------------------------------------------------------------------------------------------------------------------', '\033[0m'))
print()
print("  Another Password, but now to derive the hexadecimal Number used in the signature calculations, currently set with " + str(Password_Size) + " characters:")
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
print("  Salt used in the hashing function:")
print()
print('    {}{}{}'.format('\033[96m', RandSaltNum, '\033[0m'))
print()
print()
print("  Output with the random password hash, in encoded format (hashed by Argon2*id* version):")
print()
print('    {}{}{}'.format('\033[96m', HashingNumber[0:128], '\033[0m'))
print('    {}{}{}'.format('\033[96m', HashingNumber[128:], '\033[0m'))
print()
print(NumHashResult)
print()
print()
print("  Number used in the signature calculations, derived from the password hash above (64 hex digits [0-9A-F]):")
print()
print('        {}{}{}'.format('\033[93m', '[256 bits] [32 bytes] of length', '\033[0m'))
print()
print(RandNumResult)
print()
print('{}{}{}'.format('\033[91m', '--------------------------------------------------------------------------------------------------------------------------------------------------------------', '\033[0m'))
print()
print("  Public Key derived from Private Key using secp256k1 elliptic curve (uncompressed format, 130 hex digits [0-9A-F]):")
print()
print('        {}{}{}'.format('\033[93m', '[prefix = 04] + [32 bytes of X coordinate] + [32 bytes of Y coordinate] = Total [515 bits] [65 bytes] of length', '\033[0m'))
print()
print(PubKeyResult)
print()
print()
print("  Public Key derived from Private Key using secp256k1 elliptic curve (compressed format, 66 hex digits [0-9A-F]):")
print()
print('        {}{}{}'.format('\033[93m', '[' + prefix + '] + [32 bytes of X coordinate] = Total [258 bits] [33 bytes] of length', '\033[0m'))
print()
print(compPubKeyResult)
print()
print('{}{}{}'.format('\033[91m', '--------------------------------------------------------------------------------------------------------------------------------------------------------------', '\033[0m'))
print()
print("  Message/Transaction:")
print()
print('{}{}{}'.format('\033[96m', screenMessage, '\033[0m'))
print()
print()
print("  Hash of Message/Transaction above (64 hex digits [0-9A-F], hashed by SHA3-256):")
print()
print('        {}{}{}'.format('\033[93m', '[256 bits] [32 bytes] of length', '\033[0m'))
print()
print(MsgHashedResult)
print()
print(MsgHashResult)
print()
print('{}{}{}'.format('\033[91m', '--------------------------------------------------------------------------------------------------------------------------------------------------------------', '\033[0m'))
print()
print("  Signature Generation:")
print()
print('        {}{}{}'.format('\033[93m', 'sig(r,s) = [64 bytes] [128 hex digits] of length', '\033[0m'))
print()
print(Rr)
print(Ss)
print()
print('{}{}{}'.format('\033[91m', '--------------------------------------------------------------------------------------------------------------------------------------------------------------', '\033[0m'))
print()
print("  Signature Verification:")
print()
print(sigResult)
print()
print('{}{}{}'.format('\033[91m', '--------------------------------------------------------------------------------------------------------------------------------------------------------------', '\033[0m'))
print()
print(finalResult)
print()
