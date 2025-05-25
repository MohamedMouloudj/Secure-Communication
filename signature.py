from rsa_cipher import encrypt_rsa, decrypt_rsa, load_key_from_file
from rsa_keygen import load_key_from_file

# You'll need to import your teammate's SHA-256 implementation
# For now, I'll create a placeholder that you can replace
def sha256_custom(message):
    """
    Placeholder for custom SHA-256 implementation
    Replace this with your teammate's sha256_custom.py module
    """
    # This is a placeholder - replace with: from sha256_custom import sha256
    import hashlib
    if isinstance(message, str):
        message = message.encode('utf-8')
    return hashlib.sha256(message).digest()

def sign_message(message, private_key):
    """
    Create digital signature for message using RSA + SHA-256
    Args:
        message: string or bytes to sign
        private_key: tuple (n, d) or filename of private key
    Returns:
        signature as integer
    """
    # Load private key if filename provided
    if isinstance(private_key, str):
        private_key = load_key_from_file(private_key)
    
    # Convert message to bytes if string
    if isinstance(message, str):
        message = message.encode('utf-8')
    
    # Hash the message using SHA-256
    message_hash = sha256_custom(message)
    
    # Convert hash to integer
    hash_int = int.from_bytes(message_hash, byteorder='big')
    
    # Sign the hash using RSA private key (encrypt with private key)
    n, d = private_key
    signature = encrypt_rsa(hash_int, private_key)
    
    return signature

def verify_signature(message, signature, public_key):
    """
    Verify digital signature using RSA + SHA-256
    Args:
        message: original string or bytes that was signed
        signature: signature integer to verify
        public_key: tuple (n, e) or filename of public key
    Returns:
        True if signature is valid, False otherwise
    """
    try:
        # Load public key if filename provided
        if isinstance(public_key, str):
            public_key = load_key_from_file(public_key)
        
        # Convert message to bytes if string
        if isinstance(message, str):
            message = message.encode('utf-8')
        
        # Hash the original message
        expected_hash = sha256_custom(message)
        expected_hash_int = int.from_bytes(expected_hash, byteorder='big')
        
        # Decrypt signature using RSA public key (decrypt with public key)
        n, e = public_key
        decrypted_hash_int = decrypt_rsa(signature, public_key)
        
        # Compare the hashes
        return expected_hash_int == decrypted_hash_int
        
    except Exception as e:
        print(f"Signature verification error: {e}")
        return False

def sign_message_bytes(message, private_key):
    """
    Create digital signature and return as bytes
    Args:
        message: string or bytes to sign
        private_key: tuple (n, d) or filename of private key
    Returns:
        signature as bytes
    """
    signature_int = sign_message(message, private_key)
    
    # Convert signature to bytes
    if isinstance(private_key, str):
        private_key = load_key_from_file(private_key)
    
    n, d = private_key
    key_size = (n.bit_length() + 7) // 8
    
    return signature_int.to_bytes(key_size, byteorder='big')

def verify_signature_bytes(message, signature_bytes, public_key):
    """
    Verify digital signature from bytes
    Args:
        message: original string or bytes that was signed
        signature_bytes: signature as bytes
        public_key: tuple (n, e) or filename of public key
    Returns:
        True if signature is valid, False otherwise
    """
    # Convert signature bytes to integer
    signature_int = int.from_bytes(signature_bytes, byteorder='big')
    
    return verify_signature(message, signature_int, public_key)

def main():
    """Test digital signature functionality"""
    from rsa_keygen import generate_keys
    
    # Generate test keys
    print("Generating test keys for signature testing...")
    public_key, private_key = generate_keys(2048)
    
    # Test message
    test_message = "This is a test message for digital signature"
    print(f"\nOriginal message: {test_message}")
    
    # Sign the message
    print("Signing message...")
    signature = sign_message(test_message, private_key)
    print(f"Signature (int): {signature}")
    
    # Verify the signature
    print("Verifying signature...")
    is_valid = verify_signature(test_message, signature, public_key)
    print(f"Signature valid: {is_valid}")
    
    # Test with modified message
    print("\nTesting with modified message...")
    modified_message = "This is a MODIFIED test message for digital signature"
    is_valid_modified = verify_signature(modified_message, signature, public_key)
    print(f"Modified message signature valid: {is_valid_modified}")
    
    # Test bytes signature
    print("\nTesting bytes signature...")
    signature_bytes = sign_message_bytes(test_message, private_key)
    print(f"Signature length: {len(signature_bytes)} bytes")
    
    is_valid_bytes = verify_signature_bytes(test_message, signature_bytes, public_key)
    print(f"Bytes signature valid: {is_valid_bytes}")

if __name__ == "__main__":
    main()