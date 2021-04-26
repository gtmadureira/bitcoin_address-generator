def decodeLittleEndian(b, bits):
    return sum([b[i] << 8*i for i in range((bits+7)//8)])


def decodeScalar25519(k):
    k_list = [b for b in k]
    k_list[0] &= 248
    k_list[31] &= 127
    k_list[31] |= 64
    return decodeLittleEndian(k_list, 255)


print()
k = "47CFE2504D329742046B4F7D4F0E37ECC3F74A0BADDE52D2BD13DA6C60E790F8"
intN = decodeScalar25519(bytes.fromhex(k))
hexN = hex(intN)
print(intN)
print(str(hexN))
