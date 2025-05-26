# Secure Message Exchange Protocol

This protocol simulates a basic SSL/TLS-style secure communication using netcat for transport and Python for encryption.

---

### Key Setup

Each party generates an RSA key pair

```shell

python3 keygen_rsa.py --out sender
python3 keygen_rsa.py --out receiver
```

Exchange public keys (`sender_pub.pem`, `receiver_pub.pem`) out-of-band or hardcode them for testing.

### Sending a Message (Sender Side)

1. Generate a random AES key and IV using your custom Python logic.
2. Encrypt the **plaintext message** using your custom AES-256 (CBC mode) implementation.
3. Sign the **original plaintext** using your custom SHA-256 hash function + RSA private key (custom implementation).
4. Encrypt the AES key and IV together using the recipient's RSA **public key** (custom implementation).
5. Base64-encode the outputs.
6. Send the three lines (in order) to the receiver via `netcat`:
   - `encrypted_AES_key_and_IV`
   - `encrypted_message`
   - `digital_signature`

> python3 secure_send_custom.py <message> receiver_pub.txt sender_priv.txt | nc <receiver-host> 9999

### Receiving a Message (Receiver Side)

1. Receive three base64-encoded lines over netcat and pipe them into your custom script:
   > nc -l -p 9999 | python3 secure_receive_custom.py receiver_priv.txt sender_pub.txt
2. Read each line from standard input:

   `Line 1: encrypted_AES_key_and_IV`

   `Line 2: encrypted_message`
   
   `Line 3: digital_signature`
4. Base64-decode each part.
5. Decrypt the AES key and IV using the receiver's RSA private key (custom).
6. Decrypt the message using AES-256 in CBC mode with the decrypted key and IV.
7. Verify the digital signature using the sender’s public RSA key and your custom SHA-256.

### Message Format (Sent over netcat)

The message consists of three base64-encoded lines, sent in the following order:

- `encrypted_AES_key_and_IV`
- `encrypted_message`
- `digital_signature`

Each line should be processed in sequence by the receiver.
