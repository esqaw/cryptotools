from cryptotools.cipher.block import blockify
from cryptotools.xor import xor_bytes
from itertools import zip_longest


def irevere(arraylike):
    i = len(arraylike)
    while i > 0:
        i -= 1
        yield arraylike[i]


def add_bytes(bytes1, bytes2):
    _bytes = []
    carrage = 0
    for b1, b2 in zip_longest(irevere(bytes1), irevere(bytes2), fillvalue=0):
        _sum = b1 + b2 + carrage
        _bytes.append(_sum % 256)
        carrage = _sum // 256
    _bytes.reverse()
    return bytes(_bytes)


def CTR_decrypt(ciphertext,
                key,
                block_length,
                pseudo_random_function):
    blocks = blockify(ciphertext, block_length)
    iv = next(blocks)
    message = []
    for indx, block in enumerate(blocks):
        message.append(xor_bytes(
            pseudo_random_function(key, add_bytes(iv, [indx])),
            block))
    message = b''.join(message)
    return message
