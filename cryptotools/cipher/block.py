def blockify(ciphertext, length):
    for indx, _ in enumerate(ciphertext[::length]):
        yield ciphertext[indx * length: (indx + 1) * length]
