# RSA Implementation Documentation

## Overview
This documentation covers the RSA cryptographic components for the Secure Message Exchange Protocol, including key generation, encryption/decryption, and digital signatures.

## Components

### 1. RSA Key Generation (`rsa_keygen.py`)
**Purpose:** Generate cryptographically secure RSA key pairs from scratch.

**Key Features:**
- Miller-Rabin primality testing for secure prime generation
- 2048-bit keys by default (configurable)
- Computes RSA parameters: n = p × q, φ(n) = (p-1)(q-1)
- Uses e = 65537, calculates d using extended Euclidean algorithm

**Functions:**
- `generate_keys(bits=2048)` → Returns (public_key, private_key) tuples
- `save_key_to_file(key, filename)` → Saves key to text file
- `load_key_from_file(filename)` → Loads key from text file
- `miller_rabin(n, k=40)` → Primality test with k rounds

### 2. RSA Encryption/Decryption (`rsa_cipher.py`)
**Purpose:** Perform RSA encryption and decryption operations.

**Key Features:**
- Fast modular exponentiation using binary method
- Supports both integer and byte data
- Public key encryption: c = m^e mod n
- Private key decryption: m = c^d mod n

**Functions:**
- `encrypt_rsa(message, public_key)` → Encrypts message using public key
- `decrypt_rsa(ciphertext, private_key)` → Decrypts using private key
- `encrypt_bytes_rsa(data, public_key)` → Encrypts byte data
- `decrypt_to_bytes_rsa(ciphertext, private_key)` → Decrypts to bytes

### 3. Digital Signatures (`signature.py`)
**Purpose:** Create and verify digital signatures using RSA + SHA-256.

**Key Features:**
- Signs message hash using RSA private key
- Verifies signatures using RSA public key
- Compatible with custom SHA-256 implementation
- Supports both integer and byte signature formats

**Functions:**
- `sign_message(message, private_key)` → Creates digital signature
- `verify_signature(message, signature, public_key)` → Verifies signature
- `sign_message_bytes(message, private_key)` → Returns signature as bytes
- `verify_signature_bytes(message, signature_bytes, public_key)` → Verifies byte signature

### 4. Command-Line Key Generator (`keygen_rsa.py`)
**Purpose:** Command-line interface for key generation compatible with the protocol.

## Usage Instructions

### Generate RSA Key Pairs
```bash
# Generate sender keys
python3 keygen_rsa.py --out sender

# Generate receiver keys  
python3 keygen_rsa.py --out receiver

# Generate with custom key size
python3 keygen_rsa.py --out sender --bits 4096
```

**Output Files:**
- `sender_pub.txt` - Sender's public key (n, e)
- `sender_priv.txt` - Sender's private key (n, d)
- `receiver_pub.txt` - Receiver's public key (n, e)
- `receiver_priv.txt` - Receiver's private key (n, d)

### File Format
Keys are stored as plain text with two lines:
```
<modulus_n>
<exponent>
```

### Python Integration Examples

#### Basic Key Generation
```python
from rsa_keygen import generate_keys, save_key_to_file

# Generate 2048-bit key pair
public_key, private_key = generate_keys(2048)

# Save keys
save_key_to_file(public_key, "my_pub.txt")
save_key_to_file(private_key, "my_priv.txt")
```

#### Encryption/Decryption
```python
from rsa_cipher import encrypt_rsa, decrypt_rsa, load_key_from_file

# Load keys
public_key = load_key_from_file("receiver_pub.txt")
private_key = load_key_from_file("receiver_priv.txt")

# Encrypt message
message = b"Secret message"
ciphertext = encrypt_rsa(message, public_key)

# Decrypt message
decrypted = decrypt_rsa(ciphertext, private_key)
```

#### Digital Signatures
```python
from signature import sign_message, verify_signature

# Sign a message
message = "Important message"
signature = sign_message(message, "sender_priv.txt")

# Verify signature
is_valid = verify_signature(message, signature, "sender_pub.txt")
print(f"Signature valid: {is_valid}")
```

## Security Features

### Prime Generation
- Uses Miller-Rabin test with 40 rounds (probability of composite < 2^-80)
- Generates cryptographically strong primes
- Ensures p ≠ q for distinct prime factors

### Key Parameters
- Default 2048-bit keys (considered secure until ~2030)
- Public exponent e = 65537 (recommended standard)
- Private exponent d calculated using extended Euclidean algorithm

### Implementation Security
- No external cryptographic libraries used
- Custom modular arithmetic prevents timing attacks
- Proper random number generation for prime candidates

## Integration Notes

### SHA-256 Integration
The signature module requires a custom SHA-256 implementation from your teammate. To integrate:

**Current State:** `signature.py` contains a placeholder SHA-256 function using Python's built-in hashlib for testing.

**Integration Steps:**
1. Remove the placeholder `sha256_custom()` function from `signature.py`
2. Add the import statement at the top of the file:
   ```python
   from sha256_custom import sha256 as sha256_custom
   ```
3. Ensure your teammate's `sha256_custom.py` module is in the same directory

**Expected Function Signature:**
```python
def sha256(message): 
    # message: bytes or string
    # returns: 32-byte hash digest
```

### Protocol Compatibility
- Key files use `.txt` extension as required by protocol
- File format matches expected structure for secure messaging
- Functions accept both file paths and key tuples for flexibility

## Testing

### Run Individual Tests
```bash
# Test key generation
python3 rsa_keygen.py

# Test encryption/decryption
python3 rsa_cipher.py

# Test digital signatures
python3 signature.py
```

### Verify Key Generation
```bash
# Generate test keys
python3 keygen_rsa.py --out test

# Check files created
ls test_*.txt
```

## Error Handling

### Common Issues
- **"Message too large"**: RSA can only encrypt data smaller than key size
- **"Modular inverse does not exist"**: Rare issue with key generation
- **File not found**: Ensure key files exist and paths are correct

### Debug Tips
- Verify key file format (two lines: n, then exponent)
- Check file permissions for key files
- Ensure sufficient entropy for prime generation

This RSA implementation provides a solid foundation for the secure messaging protocol while maintaining security best practices and educational value through custom implementations.