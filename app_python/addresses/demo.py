# Generating random number
import random
private_key = (random.getrandbits(256)).to_bytes(32, byteorder="little", signed=False)

# Attaching private key to SECP256k1 using ECDSA
import ecdsa
signing_key = ecdsa.SigningKey.from_string(private_key, curve = ecdsa.SECP256k1)

verifying_key = signing_key.get_verifying_key()

# Getting the compressed public key
x_cor = bytes.fromhex(verifying_key.to_string().hex())[:32]         # The first 32 bytes are the x cordinate.
y_cor = bytes.fromhex(verifying_key.to_string().hex())[32:]         # The last 32 bytes are the y cordinate.
if int.from_bytes(y_cor, byteorder="big", signed=True) % 2 == 0:    # We need to turn the y_cor (bytes) into a number.
    public_key = bytes.fromhex(f'02{x_cor.hex()}')
else:
    public_key = bytes.fromhex(f'03{x_cor.hex()}')
    
import hashlib

# Generating keyhash
sha256_1 = hashlib.sha256(public_key)

ripemd160 = hashlib.new("ripemd160")
ripemd160.update(sha256_1.digest())

keyhash = ripemd160.digest()

# Placing keyhash in a P2WPKH_VO script
P2WPKH_VO = bytes.fromhex(f'0014{keyhash.hex()}')

# Hashing P2WPKH_VO script
sha256_P2WPKH_VO = hashlib.sha256(P2WPKH_VO)

ripemd160_P2WPKH_VO = hashlib.new("ripemd160")
ripemd160_P2WPKH_VO.update(sha256_P2WPKH_VO.digest())

hashed_P2WPKH_VO = ripemd160_P2WPKH_VO.digest()

# Nesting hashed P2WPKH_VO inside a P2SH
P2SH_P2WPKH_V0 = bytes.fromhex(f'a9{hashed_P2WPKH_VO.hex()}87')

# Getting checksum
checksum_full = hashlib.sha256(hashlib.sha256(bytes.fromhex(f'05{hashed_P2WPKH_VO.hex()}')).digest()).digest()
checksum = checksum_full[:4]

# Assembling the nested address
bin_addr = bytes.fromhex(f'05{hashed_P2WPKH_VO.hex()}{checksum.hex()}')

# Encode nested address in base58
import base58
nested_address = base58.b58encode(bin_addr)

## BECH32 (https://github.com/sipa/bech32/tree/master/ref/python)
CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
def bech32_polymod(values):
    """Internal function that computes the Bech32 checksum."""
    generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ value
        for i in range(5):
            chk ^= generator[i] if ((top >> i) & 1) else 0
    return chk

def bech32_hrp_expand(hrp):
    """Expand the HRP into values for checksum computation."""
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]

def bech32_verify_checksum(hrp, data):
    """Verify a checksum given HRP and converted data characters."""
    return bech32_polymod(bech32_hrp_expand(hrp) + data) == 1

def bech32_create_checksum(hrp, data):
    """Compute the checksum values given HRP and data."""
    values = bech32_hrp_expand(hrp) + data
    polymod = bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]

def bech32_encode(hrp, data):
    """Compute a Bech32 string given HRP and data values."""
    combined = data + bech32_create_checksum(hrp, data)
    return hrp + '1' + ''.join([CHARSET[d] for d in combined])

def bech32_decode(bech):
    """Validate a Bech32 string, and determine HRP and data."""
    if ((any(ord(x) < 33 or ord(x) > 126 for x in bech)) or
            (bech.lower() != bech and bech.upper() != bech)):
        return (None, None)
    bech = bech.lower()
    pos = bech.rfind('1')
    if pos < 1 or pos + 7 > len(bech) or len(bech) > 90:
        return (None, None)
    if not all(x in CHARSET for x in bech[pos+1:]):
        return (None, None)
    hrp = bech[:pos]
    data = [CHARSET.find(x) for x in bech[pos+1:]]
    if not bech32_verify_checksum(hrp, data):
        return (None, None)
    return (hrp, data[:-6])

def convertbits(data, frombits, tobits, pad=True):
    """General power-of-2 base conversion."""
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret

def decode(hrp, addr):
    """Decode a segwit address."""
    hrpgot, data = bech32_decode(addr)
    if hrpgot != hrp:
        return (None, None)
    decoded = convertbits(data[1:], 5, 8, False)
    if decoded is None or len(decoded) < 2 or len(decoded) > 40:
        return (None, None)
    if data[0] > 16:
        return (None, None)
    if data[0] == 0 and len(decoded) != 20 and len(decoded) != 32:
        return (None, None)
    return (data[0], decoded)

def encode(hrp, witver, witprog):
    """Encode a segwit address."""
    ret = bech32_encode(hrp, [witver] + convertbits(witprog, 8, 5))
    if decode(hrp, ret) == (None, None):
        return None
    return ret

# encoding native address in bech32
bech32 = encode('bc', 0, keyhash)

print()
print("Private Key Hexadecimal Format (64 characters [0-9A-F]):")
print(private_key.hex())
print()
print("Verifiction key:")
print(verifying_key.to_string().hex())
print()
print("Compressed public key:")
print(public_key.hex())
print()
print("keyhash:")
print(keyhash.hex())
print()
print("Native address:")
print(bech32)
print()
print("P2WPKH_V0:")
print(P2WPKH_VO.hex())
print()
print("Hashed P2WPKH_VO:")
print(hashed_P2WPKH_VO.hex())
print()
print("P2SH_P2WPKH_V0:")
print(P2SH_P2WPKH_V0.hex())
print()
print("Checksum:")
print(checksum.hex())
print()
print("Binary address:")
print(bin_addr.hex())
print()
print("Nested address:")
print(nested_address.decode())
print()