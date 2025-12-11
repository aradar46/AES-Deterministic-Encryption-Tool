# AES Deterministic Encryption Tool

A Deterministic Standalone Python Script for AES-128 CBC Encryption and Decryption.

## Features

- **Pure Python**: No external dependencies (no `pip install` required).
- **AES-128 CBC**: Uses standard AES encryption in CBC mode.
- **PKCS7 Padding**: Ensures data is properly padded.
- **Base64 Output**: Ciphertext is encoded in Base64 for easy sharing.
- **Secure Key Derivation**: Hashes your password using SHA-256 to generate a secure 16-byte key.
- **Synthetic IV (SIV)**: Derives the IV from the key and plaintext. This ensures the encryption is **deterministic** (same input + same password = same output) while being secure against pattern analysis attacks (different messages have different IVs).

## Usage

### Prerequisites

- Python 3.x installed.

### Encrypt

To encrypt a message:

```bash
python3 aes_tool.py "Your Secret Message" "YourPassword"
```

**Output:** A Base64 encoded string.

### Decrypt

To decrypt a message, use the `-d` flag:

```bash
python3 aes_tool.py -d "Base64Ciphertext" "YourPassword"
```

**Output:** The original plaintext message.

## Example

```bash
# Encrypt
python3 aes_tool.py "Hello World" "mysecret"
# Output: 2s/1c4... (some base64 string)

# Decrypt
python3 aes_tool.py -d "ZfuiTSufzt0URjpee4jOYQ==" "mysecret"
# Output: Hello World
```

## License

This project is open source and free to use.
# AES-Deterministic-Encryption-Tool
