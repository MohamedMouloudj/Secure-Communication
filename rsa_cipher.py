from rsa_keygen import load_key_from_file

def mod_exp(base, exponent, modulus):
    """Fast modular exponentiation using binary method"""
    result = 1
    base = base % modulus
    
    while exponent > 0:
        if exponent % 2 == 1:
            result = (result * base) % modulus
        exponent = exponent >> 1
        base = (base * base) % modulus
    
    return result

def bytes_to_int(data):
    """Convert bytes to integer"""
    return int.from_bytes(data, byteorder='big')

def int_to_bytes(value, length):
    """Convert integer to bytes with specified length"""
    return value.to_bytes(length, byteorder='big')

def encrypt_rsa(message, public_key):
    """
    Encrypt message using RSA public key
    Args:
        message: bytes or integer to encrypt
        public_key: tuple (n, e) or filename
    Returns:
        encrypted integer
    """
    # Load key if filename provided
    if isinstance(public_key, str):
        public_key = load_key_from_file(public_key)
    
    n, e = public_key
    
    # Convert message to integer if it's bytes
    if isinstance(message, bytes):
        # Ensure message is smaller than n
        if len(message) >= (n.bit_length() + 7) // 8:
            raise ValueError("Message too large for key size")
        message_int = bytes_to_int(message)
    else:
        message_int = message
    
    # RSA encryption: c = m^e mod n
    cipher = mod_exp(message_int, e, n)
    return cipher

def decrypt_rsa(ciphertext, private_key):
    """
    Decrypt ciphertext using RSA private key
    Args:
        ciphertext: integer to decrypt
        private_key: tuple (n, d) or filename
    Returns:
        decrypted integer
    """
    # Load key if filename provided
    if isinstance(private_key, str):
        private_key = load_key_from_file(private_key)
    
    n, d = private_key
    
    # RSA decryption: m = c^d mod n
    message = mod_exp(ciphertext, d, n)
    return message

def encrypt_bytes_rsa(data, public_key):
    """
    Encrypt bytes using RSA with proper padding consideration
    Args:
        data: bytes to encrypt
        public_key: tuple (n, e) or filename
    Returns:
        encrypted integer
    """
    if isinstance(public_key, str):
        public_key = load_key_from_file(public_key)
    
    n, e = public_key
    key_size = (n.bit_length() + 7) // 8
    
    # Ensure data fits in key size (leave room for padding)
    if len(data) >= key_size - 11:  # PKCS#1 v1.5 padding requires 11 bytes overhead
        raise ValueError(f"Data too large. Max size: {key_size - 11} bytes")
    
    return encrypt_rsa(data, public_key)

def decrypt_to_bytes_rsa(ciphertext, private_key, expected_length=None):
    """
    Decrypt RSA ciphertext to bytes
    Args:
        ciphertext: integer to decrypt
        private_key: tuple (n, d) or filename
        expected_length: expected length of decrypted data
    Returns:
        decrypted bytes
    """
    if isinstance(private_key, str):
        private_key = load_key_from_file(private_key)
    
    n, d = private_key
    key_size = (n.bit_length() + 7) // 8
    
    # Decrypt to integer
    message_int = decrypt_rsa(ciphertext, private_key)
    
    # Convert back to bytes
    if expected_length:
        return int_to_bytes(message_int, expected_length)
    else:
        # Calculate minimum bytes needed
        byte_length = (message_int.bit_length() + 7) // 8
        return int_to_bytes(message_int, byte_length)

def main():
    """Test RSA encryption/decryption"""
    from rsa_keygen import generate_keys
    
    # Generate test keys
    print("Generating test keys...")
    public_key, private_key = generate_keys(2048)
    
    # Test with integer
    print("\nTesting integer encryption:")
    test_message = 12345
    encrypted = encrypt_rsa(test_message, public_key)
    decrypted = decrypt_rsa(encrypted, private_key)
    print(f"Original: {test_message}")
    print(f"Encrypted: {encrypted}")
    print(f"Decrypted: {decrypted}")
    print(f"Match: {test_message == decrypted}")
    
    # Test with bytes
    print("\nTesting bytes encryption:")
    test_bytes = b"Hello, RSA!"
    encrypted_bytes = encrypt_bytes_rsa(test_bytes, public_key)
    decrypted_bytes = decrypt_to_bytes_rsa(encrypted_bytes, private_key, len(test_bytes))
    print(f"Original: {test_bytes}")
    print(f"Encrypted: {encrypted_bytes}")
    print(f"Decrypted: {decrypted_bytes}")
    print(f"Match: {test_bytes == decrypted_bytes}")

if __name__ == "__main__":
    main()