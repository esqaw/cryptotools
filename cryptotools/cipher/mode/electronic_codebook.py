from cryptotools.cipher.block import blockify


def ECB_decrypt(ciphertext,
                key,
                block_length,
                inverse_pseudo_random_permutation):
    message = b''.join([inverse_pseudo_random_permutation(key, block)
                        for block in blockify(ciphertext, block_length)])
    padding = message[-1]
    return message[:-padding]
