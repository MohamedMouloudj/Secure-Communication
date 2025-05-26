import random
import os

def miller_rabin(n, k=40):
    """Miller-Rabin primality test"""
    if n == 2 or n == 3:
        return True
    if n < 2 or n % 2 == 0:
        return False
    
    # Write n-1 as d * 2^r
    r = 0
    d = n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    
    # Perform k rounds of testing
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        
        if x == 1 or x == n - 1:
            continue
            
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    
    return True

def generate_prime(bits):
    """Generate a prime number with specified bit length"""
    while True:
        # Generate random odd number
        candidate = random.getrandbits(bits)
        candidate |= (1 << bits - 1) | 1  # Set MSB and LSB to 1
        
        if miller_rabin(candidate):
            return candidate

def gcd(a, b):
    """Greatest Common Divisor using Euclidean algorithm"""
    while b:
        a, b = b, a % b
    return a

def extended_gcd(a, b):
    """Extended Euclidean Algorithm"""
    if a == 0:
        return b, 0, 1
    
    gcd_val, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    
    return gcd_val, x, y

def mod_inverse(e, phi_n):
    """Calculate modular multiplicative inverse"""
    gcd_val, x, _ = extended_gcd(e, phi_n)
    
    if gcd_val != 1:
        raise ValueError("Modular inverse does not exist")
    
    return (x % phi_n + phi_n) % phi_n

def generate_keys(bits=2048):
    """
    Generate RSA key pair
    Returns: (public_key, private_key) where each key is (n, exponent)
    """
    # Generate two distinct primes
    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)
    
    # Ensure p != q
    while p == q:
        q = generate_prime(bits // 2)
    
    # Calculate n and phi(n)
    n = p * q
    phi_n = (p - 1) * (q - 1)
    
    # Choose e (commonly 65537)
    e = 65537
    
    # Ensure gcd(e, phi_n) = 1
    while gcd(e, phi_n) != 1:
        e += 2
    
    # Calculate d (private exponent)
    d = mod_inverse(e, phi_n)
    
    # Public key: (n, e), Private key: (n, d)
    public_key = (n, e)
    private_key = (n, d)
    
    return public_key, private_key

def save_key_to_file(key, filename):
    """Save key tuple (n, exponent) to file"""
    n, exponent = key
    with open(filename, 'w') as f:
        f.write(f"{n}\n{exponent}\n")

def load_key_from_file(filename):
    """Load key tuple (n, exponent) from file"""
    with open(filename, 'r') as f:
        lines = f.read().strip().split('\n')
        n = int(lines[0])
        exponent = int(lines[1])
        return (n, exponent)

def main():
    """Generate and save RSA key pair"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Generate RSA key pair')
    parser.add_argument('--out', required=True, help='Output filename prefix')
    parser.add_argument('--bits', type=int, default=2048, help='Key size in bits')
    
    args = parser.parse_args()
    
    print(f"Generating {args.bits}-bit RSA key pair...")
    public_key, private_key = generate_keys(args.bits)
    
    # Save keys
    pub_filename = f"{args.out}_pub.txt"
    priv_filename = f"{args.out}_priv.txt"
    
    save_key_to_file(public_key, pub_filename)
    save_key_to_file(private_key, priv_filename)
    
    print(f"Public key saved to: {pub_filename}")
    print(f"Private key saved to: {priv_filename}")
    print(f"Key modulus (n): {public_key[0]}")
    print(f"Public exponent (e): {public_key[1]}")

if __name__ == "__main__":
    main()