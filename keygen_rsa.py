"""
RSA Key Generation Script
Compatible with the secure message exchange protocol
"""

from rsa_keygen import generate_keys, save_key_to_file
import argparse

def main():
    parser = argparse.ArgumentParser(description='Generate RSA key pair for secure messaging')
    parser.add_argument('--out', required=True, help='Output filename prefix (e.g., "sender" creates sender_pub.txt and sender_priv.txt)')
    parser.add_argument('--bits', type=int, default=2048, help='Key size in bits (default: 2048)')
    
    args = parser.parse_args()
    
    print(f"Generating {args.bits}-bit RSA key pair...")
    
    try:
        public_key, private_key = generate_keys(args.bits)
        
        # Save keys with .txt extension for compatibility
        pub_filename = f"{args.out}_pub.txt"
        priv_filename = f"{args.out}_priv.txt"
        
        save_key_to_file(public_key, pub_filename)
        save_key_to_file(private_key, priv_filename)
        
        print(f"✓ Public key saved to: {pub_filename}")
        print(f"✓ Private key saved to: {priv_filename}")
        print(f"Key size: {args.bits} bits")
        print(f"Modulus (n): {len(str(public_key[0]))} digits")
        print("\nKey generation completed successfully!")
        
    except Exception as e:
        print(f"Error generating keys: {e}")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())