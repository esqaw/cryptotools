from itertools import tee
from cryptotools.xor import xor_bytes
from cryptotools.cipher.block import blockify


def pairwise(iterable):
    "s -> (s0,s1), (s1,s2), (s2, s3), ..."
    a, b = tee(iterable)
    next(b, None)
    return zip(a, b)


def CBC_decrypt(ciphertext,
                key,
                block_length,
                inverse_pseudo_random_permutation):
    message = []
    for previous_block, block in pairwise(blockify(ciphertext, block_length)):
        message.append(xor_bytes(inverse_pseudo_random_permutation(key, block),
                       previous_block))
    message = b''.join(message)
    padding = message[-1]
    return message[:-padding]
