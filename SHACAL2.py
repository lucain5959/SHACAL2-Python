import struct


def bytes_to_int_list(data, num_ints):
    return [int.from_bytes(data[i * 4:(i + 1) * 4], byteorder='little') for i in range(num_ints)]

def int_list_to_bytes(data):
    return b''.join([x.to_bytes(4, byteorder='little') for x in data])

def R(v, n):
    return ((v >> n) | (v << (32 - n))) & 0xFFFFFFFF

def SIG0(x):
    return R(x, 7) ^ R(x, 18) ^ (x >> 3)

def SIG1(x):
    return R(x, 17) ^ R(x, 19) ^ (x >> 10)

def EP0(x):
    return R(x, 2) ^ R(x, 13) ^ R(x, 22)

def EP1(x):
    return R(x, 6) ^ R(x, 11) ^ R(x, 25)

def CH(x, y, z):
    return ((x & y) ^ (~x & z))

def MAJ(x, y, z):
    return ((x & y) ^ (x & z) ^ (y & z))

def rev32(x):
    return struct.unpack("<I", struct.pack(">I", x))[0]

def shacal2_core(mk, data):
    K = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ]
    
    w = [0] * 64
    s = [0] * 8

    # load master key
    for i in range(16):
        w[i] = rev32(mk[i])

    # expand key
    for i in range(16, 64):
        w[i] = (SIG1(w[i - 2]) + w[i - 7] + SIG0(w[i - 15]) + w[i - 16]) & 0xFFFFFFFF

    # load 256-bit plaintext
    for i in range(8):
        s[i] = rev32(data[i])

    # encrypt
    for i in range(64):
        t1 = (s[7] + EP1(s[4]) + CH(s[4], s[5], s[6]) + w[i] + K[i]) & 0xFFFFFFFF
        t2 = (EP0(s[0]) + MAJ(s[0], s[1], s[2])) & 0xFFFFFFFF
        s[7] = s[6]
        s[6] = s[5]
        s[5] = s[4]
        s[4] = (s[3] + t1) & 0xFFFFFFFF
        s[3] = s[2]
        s[2] = s[1]
        s[1] = s[0]
        s[0] = (t1 + t2) & 0xFFFFFFFF

    # store 256-bit ciphertext
    for i in range(8):
        data[i] = rev32(s[i])

    return data

def shacal2(mk, data):
    # Ensure that the input key and data are byte strings of the correct length
    if not isinstance(mk, bytes) or len(mk) != 64:
        raise ValueError("Invalid key. Must be a 64-bytes.")
    if not isinstance(data, bytes) or len(data) != 32:
        raise ValueError("Invalid data. Must be a 32-bytes.")

    # Convert input byte strings to lists of integers
    mk_ints = bytes_to_int_list(mk, 16)
    data_ints = bytes_to_int_list(data, 8)

    # Perform Shacal-2 encryption using the integer lists
    encrypted_ints = shacal2_core(mk_ints, data_ints)

    # Convert the encrypted integer list back to a byte string
    encrypted_data = int_list_to_bytes(encrypted_ints)

    return encrypted_data

#SHACAL-2/ECB
#Source: NESSIE submission
key = bytes.fromhex('80000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000')
plaintext = bytes.fromhex('0000000000000000000000000000000000000000000000000000000000000000')
ciphertext = shacal2(key, plaintext)
print (ciphertext.hex())
