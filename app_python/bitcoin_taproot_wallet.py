"""
Program to generate bitcoin wallet address with P2TR (Pay-to-Taproot) at
main network.

For educational purposes only.

Works on Python 3.6 or higher.

    Source:

            https://github.com/gtmadureira/bitcoin_address-generator/
            /blob/main/app_python/bitcoin_taproot_wallet.py

Created by:

            • Gustavo Madureira (gtmadureira@gmail.com)
            • https://gtmadureira.github.io/
"""


from enum import Enum
from platform import system
from hmac import new as hmac
from secrets import randbits
from typing import List, Tuple, Union
from subprocess import check_call as run_command
from hashlib import pbkdf2_hmac, sha256, sha3_512


# Type hints.
Markle_Tuple = Tuple[int, bytes]
Markle_List = List[Tuple[int, bytes], ]


# Tests the operating system type and sets the screen clear command.
if system() == "Windows":

    def clear() -> None:
        """Screen clear command for Windows operating system."""
        run_command("cls")

elif system() == "Darwin" or system() == "Linux":

    def clear() -> None:
        """Screen clear command for macOS/Linux operating system."""
        run_command("clear")


# Mathematical domain parameters of the elliptic curve 'secp256k1'.
# Source: https://www.secg.org/sec2-v2.pdf
_FP_CURVE = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_A_CURVE = 0x0000000000000000000000000000000000000000000000000000000000000000
_B_CURVE = 0x0000000000000000000000000000000000000000000000000000000000000007
_GX_CURVE = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_GY_CURVE = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
_N_CURVE = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_H_CURVE = 0x0000000000000000000000000000000000000000000000000000000000000001


def modular_inverse(k: int, p: int) -> int:
    """
    Extended Euclidean algorithm/'division' in elliptic curve.
    Returns the multiplicative inverse of k modulo p. Where the only
    integer x is defined such that (x * k) % p == 1.
    k must be non-zero and p must be a prime.
    """
    if k == 0:
        raise ZeroDivisionError("Division by zero!")
    if k < 0:
        # k ** -1 = p - (-k) ** -1  (mod p)
        return p - modular_inverse(-k, p)
    # Extended Euclidean algorithm.
    s, old_s = 0, 1
    t, old_t = 1, 0
    r, old_r = p, k
    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t
    gcd, x, y = old_r, old_s, old_t
    assert gcd == 1
    assert (k * x) % p == 1
    assert (p * y) % k == 1
    return x % p


def ec_point_addition(xp: int, yp: int, xq: int, yq: int) -> tuple:
    """
    Point addition in elliptic curve. It adds Point-P with Point-Q.
    """
    m = ((yq - yp) * modular_inverse(xq - xp, _FP_CURVE)) % _FP_CURVE
    xr = (m * m - xp - xq) % _FP_CURVE
    yr = (m * (xp - xr) - yp) % _FP_CURVE
    return (xr, yr)


def ec_point_doubling(xp: int, yp: int) -> tuple:
    """Point doubling in elliptic curve. It doubles Point-P."""
    lamnumer = 3 * xp * xp + _A_CURVE
    lamdenom = 2 * yp
    lam = (lamnumer * modular_inverse(lamdenom, _FP_CURVE)) % _FP_CURVE
    xr = (lam * lam - 2 * xp) % _FP_CURVE
    yr = (lam * (xp - xr) - yp) % _FP_CURVE
    return (xr, yr)


def ec_point_multiplication(xs: int, ys: int, scalar: int) -> tuple:
    """
    Point multiplication in elliptic curve. It doubles Point-P and adds
    Point-P with Point-Q.
    """
    if not 0 < scalar < _N_CURVE:
        raise Exception("Invalid Scalar/Private Key")
    scalarbin = bin(scalar)[2:]
    qx, qy = xs, ys
    for i in range(1, len(scalarbin)):
        qx, qy = ec_point_doubling(qx, qy)
        if scalarbin[i] == "1":
            qx, qy = ec_point_addition(qx, qy, xs, ys)
    return (qx, qy)


def tagged_hash(tag: str, msg: bytes) -> bytes:
    """
    Where 'tag' is a UTF-8 encoded tag name and 'msg' is an array of
    bytes, returning the 32-byte hash.
    """
    tag_hash = sha256(tag.encode()).digest()
    return sha256(tag_hash + tag_hash + msg).digest()


def is_infinite(P: tuple) -> bool:
    """
    Returns whether or not P is the point at infinity in elliptic
    curve.
    """
    return P is None


def x(P: tuple) -> int:
    """
    Refer to the x coordinate of a point P
    (assuming it is not infinity), then returns this value.
    """
    assert not is_infinite(P)
    return P[0]


def y(P: tuple) -> int:
    """
    Refer to the y coordinate of a point P
    (assuming it is not infinity), then returns this value.
    """
    assert not is_infinite(P)
    return P[1]


def bytes_from_int(x: int) -> bytes:
    """
    Returns the 32-byte encoding of x, most significant byte first.
    """
    return x.to_bytes(32, byteorder="big")


def lift_x(b: bytes) -> tuple:
    """
    Returns the point P for which x(P) = x and has_even_y(P), or fails
    if no such point exists.
    """
    x = int_from_bytes(b)
    if x >= _FP_CURVE:
        return None  # type: ignore
    y_sq = (pow(x, 3, _FP_CURVE) + 7) % _FP_CURVE
    y = pow(y_sq, (_FP_CURVE + 1) // 4, _FP_CURVE)
    if pow(y, 2, _FP_CURVE) != y_sq:
        return None  # type: ignore
    return (x, y if y & 1 == 0 else _FP_CURVE - y)


def int_from_bytes(b: bytes) -> int:
    """
    Returns the 256-bit unsigned integer whose most significant byte
    first encoding is x.
    """
    return int.from_bytes(b, byteorder="big")


def has_even_y(P: tuple) -> bool:
    """
    Where P is a point for which not is_infinite(P),
    returns y(P) mod 2 = 0.
    """
    assert not is_infinite(P)
    return y(P) % 2 == 0


def ser_script(script: bytes) -> bytes:
    """Prefixes its input with a CompactSize-encoded length."""
    return bytes([len(script)]) + script


def taproot_tweak_public_key(internal_public_key: bytes, h: bytes) -> tuple:
    """
    Public key tweaking procedure, returning the output public key.
    """
    t = int_from_bytes(tagged_hash("TapTweak", internal_public_key + h))
    if not 0 < t < _N_CURVE:
        return (None, bytes())
    p = lift_x(internal_public_key)
    q = ec_point_multiplication(_GX_CURVE, _GY_CURVE, t)
    px, py = p
    qx, qy = q
    Q = ec_point_addition(px, py, qx, qy)
    return 0 if has_even_y(Q) else 1, bytes_from_int(x(Q))


def taproot_tree_helper(merkle_script_tree:
                        Union[Markle_Tuple, Markle_List]) -> tuple:
    """Merkle script tree builder."""
    if isinstance(merkle_script_tree, tuple):
        leaf_version, script = merkle_script_tree
        h = tagged_hash("TapLeaf", bytes([leaf_version]) + ser_script(script))
        return ([((leaf_version, script), bytes())], h)
    left, left_h = taproot_tree_helper(merkle_script_tree[0])
    right, right_h = taproot_tree_helper(merkle_script_tree[1])
    ret = [(l, c + right_h) for l, c in left] + \
        [(l, c + left_h) for l, c in right]  # noqa: E741
    if right_h < left_h:
        left_h, right_h = right_h, left_h
    return (ret, tagged_hash("TapBranch", left_h + right_h))


def taproot_output_script(internal_public_key: str, merkle_script_tree:
                          Union[Markle_Tuple, Markle_List, None]) -> bytes:
    """
    Given a internal public key and a Merkle script tree, compute the
    output script.

    Merkle script tree is either:
     - a (leaf_version, script) tuple (leaf_version is 0xc0 for
     [[bip-0342.mediawiki|BIP342]] scripts).
     - a list of two elements, each with the same structure as Merkle
     script tree itself.
     - None.
    """
    if merkle_script_tree is None:
        h = bytes()
    else:
        _, h = taproot_tree_helper(merkle_script_tree)
    _, output_pubkey = taproot_tweak_public_key(
        bytes.fromhex(internal_public_key), h)
    if not output_pubkey:
        return output_pubkey
    return bytes([0x51, 0x20]) + output_pubkey


# Alphabet used for base58 encoding.
BASE58_CHARSET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def base58_from_hex(input: str) -> str:
    """Encoder from hexadecimal to base58."""
    count = 0
    val = 0
    for char in input:
        if (char != "0"):
            break
        count += 1
    count = count // 2
    n = int(input, 16)
    output = []
    while (n > 0):
        n, remainder = divmod(n, 58)
        output.append(BASE58_CHARSET[remainder])
    while (val < count):
        output.append(BASE58_CHARSET[0])
        val += 1
    return "".join(output[::-1])


class Encoding(Enum):
    """Enumeration type to list the various supported encodings."""
    BECH32 = 1
    BECH32M = 2


# Alphabet used for Bech32/Bech32m encoding.
BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
# Constant required for Bech32m encoding.
BECH32M_CONST = 0x2bc830a3


def bech32_polymod(values: list) -> int:
    """Internal function that computes the Bech32 checksum."""
    generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ value
        for i in range(5):
            chk ^= generator[i] if ((top >> i) & 1) else 0
    return chk


def bech32_hrp_expand(hrp: str) -> list:
    """Expand the HRP into values for checksum computation."""
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def bech32_verify_checksum(hrp: str, data: list) -> object:
    """Verify a checksum given HRP and converted data characters."""
    const = bech32_polymod(bech32_hrp_expand(hrp) + data)
    if const == 1:
        return Encoding.BECH32
    if const == BECH32M_CONST:
        return Encoding.BECH32M
    return None


def bech32_create_checksum(hrp: str, data: list, spec: object) -> list:
    """Compute the checksum values given HRP and data."""
    values = bech32_hrp_expand(hrp) + data
    const = BECH32M_CONST if spec == Encoding.BECH32M else 1
    polymod = bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ const
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def bech32_encode(hrp: str, data: list, spec: object) -> str:
    """Compute a Bech32 string given HRP and data values."""
    combined = data + bech32_create_checksum(hrp, data, spec)
    return hrp + "1" + "".join([BECH32_CHARSET[d] for d in combined])


def bech32_decode(bech: str) -> tuple:
    """Validate a Bech32/Bech32m string, and determine HRP and data."""
    if ((any(ord(x) < 33 or ord(x) > 126 for x in bech)) or
            (bech.lower() != bech and bech.upper() != bech)):
        return (None, None, None)
    bech = bech.lower()
    pos = bech.rfind("1")
    if pos < 1 or pos + 7 > len(bech) or len(bech) > 90:
        return (None, None, None)
    if not all(x in BECH32_CHARSET for x in bech[pos + 1:]):
        return (None, None, None)
    hrp = bech[:pos]
    data = [BECH32_CHARSET.find(x) for x in bech[pos + 1:]]
    spec = bech32_verify_checksum(hrp, data)
    if spec is None:
        return (None, None, None)
    return (hrp, data[:-6], spec)


def convertbits(data: Union[bytes, list], frombits: int, tobits: int,
                pad: bool = True) -> list:
    """General power-of-2 base conversion."""
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None  # type: ignore
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None  # type: ignore
    return ret


def decode(hrp: str, addr: str) -> tuple:
    """Decode a segwit address."""
    hrpgot, data, spec = bech32_decode(addr)
    if hrpgot != hrp:
        return (None, None)
    decoded = convertbits(data[1:], 5, 8, False)
    if decoded is None or len(decoded) < 2 or len(decoded) > 40:
        return (None, None)
    if data[0] > 16:
        return (None, None)
    if data[0] == 0 and len(decoded) != 20 and len(decoded) != 32:
        return (None, None)
    if data[0] == 0 and spec != Encoding.BECH32 or \
            data[0] != 0 and spec != Encoding.BECH32M:
        return (None, None)
    return (data[0], decoded)


def encode(hrp: str, witver: int, witprog: bytes) -> str:
    """Encode a segwit address."""
    spec = Encoding.BECH32 if witver == 0 else Encoding.BECH32M
    ret = bech32_encode(hrp, [witver] + convertbits(witprog, 8, 5), spec)
    if decode(hrp, ret) == (None, None):
        return None  # type: ignore
    return ret


def generate_private_key() -> str:
    """Secure generator of private key at 256-bit length."""
    while True:
        entropy_data = bytes.fromhex(hex(randbits(1024))[2:].zfill(256))
        entropy_salt = bytes.fromhex(hex(randbits(128))[2:].zfill(32))
        password = "Hattoshi Hanzōmoto - The bitcoin master seed"
        entropy_salt = password.encode("utf-8") + entropy_salt
        master_seed = bytes.fromhex(pbkdf2_hmac("sha3-512",
                                                entropy_data,
                                                entropy_salt,
                                                2048, 64).hex().zfill(128))
        entropy_salt = bytes.fromhex(hex(randbits(128))[2:].zfill(32))
        password = "Hattoshi Hanzōmoto - The bitcoin master node"
        entropy_salt = password.encode("utf-8") + entropy_salt
        master_node = hmac(entropy_salt,
                           master_seed,
                           sha3_512).hexdigest().zfill(128)
        master_prvk = bytes.fromhex("00" + master_node[0:64])
        master_chcd = bytes.fromhex(master_node[64:])
        index = (2**31 + 86).to_bytes(4, byteorder="big")
        hmac_prvk_chcd = hmac(master_chcd,
                              master_prvk +
                              index, sha3_512).hexdigest().zfill(128)
        scalar_add_mod = (int("0x00" + master_node[0:64], 16) +
                          int("0x" + hmac_prvk_chcd[0:64], 16)) % _N_CURVE
        private_key = hex(scalar_add_mod)[2:].zfill(64)
        if not 0 < int("0x" + private_key, 16) < _N_CURVE:
            continue
        break
    return private_key


def private_key_to_wif(private_key: str) -> str:
    """
    Private key encoder to compressed WIF (Wallet Import Format),
    coded to main network.
    """
    var = "80" + private_key + "01"
    checksum = sha256(sha256(bytes.fromhex(var)).digest()
                      ).hexdigest().zfill(64)
    return base58_from_hex(var + checksum[0:8])


def get_public_key_from_private_key(private_key: str) -> str:
    """
    Gets the public key by multiplying (in the elliptical curve) the
    private key with the generating points, thus returning compressed
    format of public key.
    """
    x_public_key, y_public_key = ec_point_multiplication(
        _GX_CURVE, _GY_CURVE, int("0x" + private_key, 16))
    if y_public_key % 2 == 1:
        return "03" + hex(x_public_key)[2:].zfill(64)
    else:
        return "02" + hex(x_public_key)[2:].zfill(64)


def public_key_to_address(output_public_key: str) -> str:
    """
    Output public key encoder to P2TR (Pay-to-Taproot) address, coded
    to main network.
    """
    return encode("bc", 1, bytes.fromhex(output_public_key))


if __name__ == "__main__":
    clear()
    while True:
        private_key = generate_private_key()
        private_key_wif = private_key_to_wif(private_key)
        public_key = get_public_key_from_private_key(private_key)
        internal_public_key = public_key[2:]
        markle_script_tree = None
        script_public_key = taproot_output_script(
            internal_public_key, markle_script_tree).hex()
        if not script_public_key:
            continue
        break
    output_public_key = script_public_key[4:]
    address = public_key_to_address(output_public_key)
    data = (private_key.upper(),
            private_key_wif,
            public_key.upper(),
            internal_public_key.upper(),
            script_public_key.upper(),
            output_public_key.upper(),
            address)
    print("\n\t              Private Key Hexadecimal: " + data[0] +
          "\n\t Private Key Compressed WIF @ MainNet: \033[92m" + data[1] +
          "\033[0m\n\t                Compressed Public Key: " + data[2] +
          "\n\t                  Internal Public Key: " + data[3] +
          "\n\t                    Script Public Key: " + data[4] +
          "\n\t                    Output Public Key: " + data[5] +
          "\n\t               P2TR Address @ MainNet: \033[92m" + data[6] +
          "\033[0m\n")
