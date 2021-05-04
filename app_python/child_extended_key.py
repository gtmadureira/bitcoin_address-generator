import hashlib
import hmac

# secp256k1 domain parameters.
Pcurve = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F # The proven prime.
Acurve = 0x0000000000000000000000000000000000000000000000000000000000000000 # These two values defines the elliptic curve.
Bcurve = 0x0000000000000000000000000000000000000000000000000000000000000007 # y^2 = x^3 + Acurve * x + Bcurve.
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798 # This is the x coordinate of the generating point.
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8 # This is the y coordinate of the generating point.
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 # Number of points in the field.

def modinv(a, n = Pcurve): # Extended euclidean algorithm/'division' in elliptic curves.
    lm, hm = 1, 0
    low, high = a % n, n
    while low > 1:
        ratio = high // low
        nm, new = hm - lm * ratio, high - low * ratio
        lm, low, hm, high = nm, new, lm, low
    return lm % n

def ecadd(xp, yp, xq, yq): # Not true addition, invented for EC. It adds Point-P with Point-Q.
    m = ((yq - yp) * modinv(xq - xp, Pcurve) % Pcurve)
    xr = (m * m - xp - xq) % Pcurve
    yr = (m * (xp - xr) - yp) % Pcurve
    return (xr, yr)

def ecdouble(xp, yp): # EC point doubling, invented for EC. It doubles Point-P.
    LamNumer = 3 * xp * xp + Acurve
    LamDenom = 2 * yp
    Lam = (LamNumer * modinv(LamDenom, Pcurve)) % Pcurve
    xr = (Lam * Lam - 2 * xp) % Pcurve
    yr = (Lam * (xp - xr) - yp) % Pcurve
    return (xr, yr)

def ecmultiply(xs, ys, Scalar): # Double & Add. EC multiplication, not true multiplication.
    ScalarBin = str(bin(Scalar))[2:]
    Qx, Qy = xs, ys
    for i in range (1, len(ScalarBin)): # This is invented EC multiplication.
        Qx, Qy = ecdouble(Qx, Qy) # print "DUB", Qx; print.
        if ScalarBin[i] == "1":
            Qx, Qy = ecadd(Qx, Qy, xs, ys) # print "ADD", Qx; print.
    return (Qx, Qy)

def int_to_bytes(x: int) -> bytes:
    return x.to_bytes(4, byteorder = 'big')

def extended_key_tree(private_key: str, chain_code: str, purpose: int,
                      coin_type: int, account: int,index_change_receiving: int,
                      index_address: int ) -> str:
    
    # Purpose    
    index = 2**31 + purpose
    hmachash = hmac.new(bytes.fromhex(chain_code), bytes.fromhex(private_key) + int_to_bytes(index),
                        hashlib.sha512).hexdigest().zfill(128).upper()
    scalar_add_mod = (int("0x" + private_key, 16) + int("0x" + hmachash[0:64], 16)) % N
    newkey_a = hex(scalar_add_mod)[2:].zfill(64).upper() + hmachash[64:]

    # Coin Type
    index = 2**31 + coin_type
    hmachash = hmac.new(bytes.fromhex(newkey_a[64:]), bytes.fromhex("00" + newkey_a[0:64]) + int_to_bytes(index),
                        hashlib.sha512).hexdigest().zfill(128).upper()
    scalar_add_mod = (int("0x00" + newkey_a[0:64], 16) + int("0x" + hmachash[0:64], 16)) % N
    newkey_b = hex(scalar_add_mod)[2:].zfill(64).upper() + hmachash[64:]

    # Account
    index = 2**31 + account
    hmachash = hmac.new(bytes.fromhex(newkey_b[64:]), bytes.fromhex("00" + newkey_b[0:64]) + int_to_bytes(index),
                        hashlib.sha512).hexdigest().zfill(128).upper()
    scalar_add_mod = (int("0x00" + newkey_b[0:64], 16) + int("0x" + hmachash[0:64], 16)) % N
    newkey_c= hex(scalar_add_mod)[2:].zfill(64).upper() + hmachash[64:]
    
    # Receiving or Change
    publickey = ecmultiply(Gx, Gy, int("0x" + newkey_c[0:64], 16))

    if publickey[1] % 2 == 1: # If the Y coordinate of the Public Key is odd.
        publickey = "03" + hex(publickey[0])[2:].zfill(64).upper()
    else: # If the Y coordinate of the Public Key is even.
        publickey = "02" + hex(publickey[0])[2:].zfill(64).upper()
    
    index = index_change_receiving
    hmachash = hmac.new(bytes.fromhex(newkey_c[64:]), bytes.fromhex(publickey) + int_to_bytes(index),
                        hashlib.sha512).hexdigest().zfill(128).upper()
    scalar_add_mod = (int("0x" + newkey_c[0:64], 16) + int("0x" + hmachash[0:64], 16)) % N
    newkey_d = hex(scalar_add_mod)[2:].zfill(64).upper() + hmachash[64:]
    
    # Address
    publickey = ecmultiply(Gx, Gy, int("0x" + newkey_d[0:64], 16))

    if publickey[1] % 2 == 1: # If the Y coordinate of the Public Key is odd.
        publickey = "03" + hex(publickey[0])[2:].zfill(64).upper()
    else: # If the Y coordinate of the Public Key is even.
        publickey = "02" + hex(publickey[0])[2:].zfill(64).upper()
    
    index = index_address
    hmachash = hmac.new(bytes.fromhex(newkey_d[64:]), bytes.fromhex(publickey) + int_to_bytes(index),
                        hashlib.sha512).hexdigest().zfill(128).upper()
    scalar_add_mod = (int("0x" + newkey_d[0:64], 16) + int("0x" + hmachash[0:64], 16)) % N
    newkey_e = hex(scalar_add_mod)[2:].zfill(64).upper() + hmachash[64:]
    
    return newkey_e[0:64]

"""

BIP39 - Mnemonic Phrase:

series swamp veteran alien hub lazy gauge blouse barrel width sun catalog correct huge snow fox tennis sad apology focus home agent comfort clay


BIP39 - Master Seed:

D8A02A07C8F90457E74C507181263C3C16F731E863DE9620A6D36269ADF509B516D317890E225E4969444C593E5E7C1004A0248C3D92618632FF997C74F8F12C


Non-Serialized Master Node (Root Extended Private Key):

43AC0A818A2FCE8564E599EE856593647FB749691A528F29CA043B5D8970DE79735BFD10E4C99A58EC48D85DD745C24A1DE5A10EE940017318A20042C9820DE6

"""

# Master Private Key with prepend 0x00.
privk = "00" + "43AC0A818A2FCE8564E599EE856593647FB749691A528F29CA043B5D8970DE79"

# Master Chain Code.
chcod = "735BFD10E4C99A58EC48D85DD745C24A1DE5A10EE940017318A20042C9820DE6"

print(extended_key_tree(privk, chcod, 84, 0, 0, 0, 0))
