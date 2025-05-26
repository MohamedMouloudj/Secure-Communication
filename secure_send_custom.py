from rsa_keygen import generate_keys, save_key_to_file, load_key_from_file
from rsa_cipher import encrypt_rsa, decrypt_rsa, encrypt_bytes_rsa, decrypt_to_bytes_rsa
from signature import sign_message, verify_signature, sign_message_bytes, verify_signature_bytes
from aes_custom import encrypt_aes, decrypt_aes, aes_key_generation
import sys
import json
import base64

def generate_custom_keys(bits=2048, out_prefix="custom"):
    """
    Generate RSA key pair with custom output filenames
    Args:
        bits: key size in bits
        out_prefix: output filename prefix
    Returns:
        None
    """
    print(f"Generating {bits}-bit RSA key pair...")
    
    try:
        public_key, private_key = generate_keys(bits)
        
        # Save keys with custom filenames
        pub_filename = f"{out_prefix}_pub.txt"
        priv_filename = f"{out_prefix}_priv.txt"
        
        save_key_to_file(public_key, pub_filename)
        save_key_to_file(private_key, priv_filename)

        return pub_filename, priv_filename
        
    except Exception as e:
        print(f"Error generating keys: {e}")
        return 1


def load_keys(private_key_file, public_key_file):
    """
    Load RSA keys from files
    Args:
        private_key_file: filename of private key
        public_key_file: filename of public key
    Returns:
        tuple: (public_key, private_key)
    """
    try:
        public_key = load_key_from_file(public_key_file)
        private_key = load_key_from_file(private_key_file)
        return public_key, private_key
    except Exception as e:
        print(f"Error loading keys: {e}")
        return None, None

def asymmetric_encrypt(data, public_key):
    """
    Encrypt data using RSA public key
    Args:
        data: integer or bytes to encrypt
        public_key: tuple (n, e) or filename of public key
    Returns:
        encrypted data as integer or bytes
    """
    if isinstance(public_key, str):
        public_key = load_key_from_file(public_key)
    
    if isinstance(data, int):
        return encrypt_rsa(data, public_key)
    elif isinstance(data, bytes):
        return encrypt_bytes_rsa(data, public_key)
    else:
        raise ValueError("Data must be an integer or bytes")

def asymmetric_decrypt(ciphertext, private_key):
    """
    Decrypt ciphertext using RSA private key
    Args:
        ciphertext: integer or bytes to decrypt
        private_key: tuple (n, d) or filename of private key
    Returns:
        decrypted data as integer or bytes
    """
    if isinstance(private_key, str):
        private_key = load_key_from_file(private_key)
    
    if isinstance(ciphertext, int):
        return decrypt_rsa(ciphertext, private_key)
    elif isinstance(ciphertext, bytes):
        return decrypt_to_bytes_rsa(ciphertext, private_key)
    else:
        raise ValueError("Ciphertext must be an integer or bytes")
    
def sign_data(message, private_key):
    """
    Sign data using RSA private key
    Args:
        message: string or bytes to sign
        private_key: tuple (n, d) or filename of private key
    Returns:
        signature as integer
    """
    return sign_message_bytes(message, private_key)

def verify_data_signature(message, signature, public_key):
    """
    Verify digital signature using RSA public key
    Args:
        message: original string or bytes that was signed
        signature: signature integer to verify
        public_key: tuple (n, e) or filename of public key
    Returns:
        True if signature is valid, False otherwise
    """
    return verify_signature_bytes(message, signature, public_key)

def generate_symmetric_key():
    """
    Generate a symmetric encryption key and IV for AES
    Returns:
        tuple: (key, iv)
    """
    return aes_key_generation()

def symmetric_encrypt(data, key, iv):
    """
    Symmetric encryption with AES
    Args:
        data: bytes to encrypt
        key: symmetric key
        iv: initialization vector
    Returns:
        encrypted data as bytes
    """
    return encrypt_aes(data, key, iv)

def symmetric_decrypt(ciphertext, key, iv):
    """
    Symmetric decryption with AES
    Args:
        ciphertext: bytes to decrypt
        key: symmetric key
        iv: initialization vector
    Returns:
        decrypted data as bytes
    """
    return decrypt_aes(ciphertext, key, iv)


def main():

    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} receiver_pub_key sender_priv_key", file=sys.stderr)
        sys.exit(1)

    receiver_pub_key_file = sys.argv[1]
    sender_priv_key_file = sys.argv[2]

    # Load keys
    receiver_pub_key = load_key_from_file(receiver_pub_key_file)
    sender_priv_key = load_key_from_file(sender_priv_key_file)

    if not receiver_pub_key or not sender_priv_key:
        print("Failed to load keys", file=sys.stderr)
        sys.exit(1)

    # Generate symmetric key for this session
    aes_key, aes_iv = generate_symmetric_key()
    print(f"Generated AES key for secure communication", file=sys.stderr)

    # Encrypt the symmetric key with receiver's public key
    encrypted_key = asymmetric_encrypt(aes_key, receiver_pub_key)
    encrypted_iv = asymmetric_encrypt(aes_iv, receiver_pub_key)
    
    # Sign the encrypted key with sender's private key
    key_signature = sign_data(encrypted_key.to_bytes((encrypted_key.bit_length() + 7) // 8, byteorder='big'), sender_priv_key)
    iv_signature = sign_data(encrypted_iv.to_bytes((encrypted_iv.bit_length() + 7) // 8, byteorder='big'), sender_priv_key)


    # Send the encrypted key and signature
    key_package = {
        "key_signature": base64.b64encode(key_signature).decode('utf-8'),
        "iv_signature": base64.b64encode(iv_signature).decode('utf-8'),
        "encrypted_key": base64.b64encode(
            encrypted_key.to_bytes((encrypted_key.bit_length() + 7) // 8, byteorder='big')
        ).decode('utf-8'),

        "encrypted_iv": base64.b64encode(
            encrypted_iv.to_bytes((encrypted_iv.bit_length() + 7) // 8, byteorder='big')
        ).decode('utf-8'),

        "type": "key_exchange"
    }
    
    # Send the initial key package
    print(json.dumps(key_package))
    sys.stdout.flush()

    # Message exchange loop
    try:
        print("Secure messaging started. Type your messages:", file=sys.stderr)
        while True:
            message = input()
            
            if message.lower() == 'exit':
                break

            # Encrypt the message using the symmetric key
            encrypted_message = symmetric_encrypt(message.encode('utf-8'), aes_key, aes_iv)
            
            # Sign the encrypted message
            message_signature = sign_data(encrypted_message, sender_priv_key)
            
            # Create the message package
            message_package = {
                "encrypted_message": base64.b64encode(encrypted_message).decode('utf-8'),
                "message_signature": base64.b64encode(message_signature).decode('utf-8'),
                "type": "message"
            }
            
            print(json.dumps(message_package))
            sys.stdout.flush()
            
    except KeyboardInterrupt:
        print("\nExiting...", file=sys.stderr)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)

if __name__ == "__main__":
    main()