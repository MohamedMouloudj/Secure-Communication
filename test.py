from aes_custom import encrypt_aes, decrypt_aes 
from sha256_custom import sha256

def test_sha256():
    msg = b"abc"
    expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    result = sha256(msg)
    print("SHA-256 OK?" , result == expected)
    print("Result :", result)
    print("Expected:", expected)
    print()

def test_aes():
    key = b'This_is_a_256_bit_key_for_AES!!'[:32]  # 32-byte key
    iv = b'This_is_an_IV456'                      # 16-byte IV
    plaintext = b"Secret message needs AES CBC!"

    print("Original:", plaintext)

    encrypted = encrypt_aes(plaintext, key, iv)
    print("Encrypted (hex):", encrypted.hex())

    decrypted = decrypt_aes(encrypted, key, iv)
    print("Decrypted:", decrypted)

    print("AES CBC OK?", decrypted == plaintext)
    print()

if __name__ == "__main__":
    print("==== SHA-256 TEST ====")
    test_sha256()
    print("==== AES-256 CBC TEST ====")
    test_aes()