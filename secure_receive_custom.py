from rsa_keygen import generate_keys, save_key_to_file, load_key_from_file
from rsa_cipher import encrypt_rsa, decrypt_rsa, encrypt_bytes_rsa, decrypt_to_bytes_rsa
from signature import sign_message, verify_signature, sign_message_bytes, verify_signature_bytes
from aes_custom import encrypt_aes, decrypt_aes, aes_key_generation
import sys
import json
import base64

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
        print(f"Usage: {sys.argv[0]} receiver_priv_key sender_pub_key", file=sys.stderr)
        sys.exit(1)

    receiver_priv_key_file = sys.argv[1]
    sender_pub_key_file = sys.argv[2]

    # Load keys
    receiver_priv_key = load_key_from_file(receiver_priv_key_file)
    sender_pub_key = load_key_from_file(sender_pub_key_file)

    if not receiver_priv_key or not sender_pub_key:
        print("Failed to load keys", file=sys.stderr)
        sys.exit(1)

    # Wait for the key exchange message
    print("Waiting for secure communication...", file=sys.stderr)
    
    try:
        aes_key = None
        aes_iv = None
        
        while True:
            line = input()
            data = json.loads(line)
            
            # Handle key exchange
            if data["type"] == "key_exchange":
                # Get the encrypted key and signature
                encrypted_key = base64.b64decode(data["encrypted_key"])
                key_signature = base64.b64decode(data["key_signature"])
                encrypted_iv = base64.b64decode(data["encrypted_iv"])
                iv_signature = base64.b64decode(data["iv_signature"])
                
                # Verify signatures
                if not verify_data_signature(encrypted_key, key_signature, sender_pub_key):
                    print("Invalid key signature! Potential security breach.", file=sys.stderr)
                    continue
                
                if not verify_data_signature(encrypted_iv, iv_signature, sender_pub_key):
                    print("Invalid IV signature! Potential security breach.", file=sys.stderr)
                    continue
                
                # Decrypt the AES key and IV with receiver's private key
                aes_key_int = asymmetric_decrypt(int.from_bytes(encrypted_key, byteorder='big'), receiver_priv_key)
                aes_iv_int = asymmetric_decrypt(int.from_bytes(encrypted_iv, byteorder='big'), receiver_priv_key)

                aes_key = aes_key_int.to_bytes(32, byteorder='big')
                aes_iv = aes_iv_int.to_bytes(16, byteorder='big') 
                
                print("Secure communication established.", file=sys.stderr)
                
            # Handle encrypted messages
            elif data["type"] == "message":
                if not aes_key or not aes_iv:
                    print("Error: No secure channel established yet.", file=sys.stderr)
                    continue
                    
                # Get the encrypted message and signature
                encrypted_message = base64.b64decode(data["encrypted_message"])
                message_signature = base64.b64decode(data["message_signature"])
                
                # Verify the message signature
                if not verify_data_signature(encrypted_message, message_signature, sender_pub_key):
                    print("Invalid message signature! Message may be tampered.", file=sys.stderr)
                    continue
                
                # Decrypt the message
                decrypted_message = symmetric_decrypt(encrypted_message, aes_key, aes_iv)
                
                # Display the message
                print(f"Received: {decrypted_message.decode('utf-8')}")
                sys.stdout.flush()
                
    except KeyboardInterrupt:
        print("\nExiting...", file=sys.stderr)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)

if __name__ == "__main__":
    main()