# pswd_encrpt

Simple CLI utility to encrypt and decrypt passwords securely.

## Features
- AES-256 encryption (password/key based)
- Encrypt and decrypt strings or files
- Cross-platform (Windows, macOS, Linux)
- Minimal dependencies

## Requirements
- Python 3.8+ (or adjust for your language of choice)
- pip packages: cryptography

## Installation
```bash
git clone <repo-url>
cd pswd_encrpt
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Usage
Encrypt a password:
```bash
python encrypt.py --encrypt --input "my-secret-password" --key "master-key"
```
Decrypt:
```bash
python encrypt.py --decrypt --input "<ciphertext>" --key "master-key"
```
Encrypt a file:
```bash
python encrypt.py --encrypt-file secrets.txt --out secrets.enc --key "master-key"
```

## Configuration
- Use a strong, unique key. Consider deriving keys with PBKDF2/HKDF from a passphrase.
- Store keys in a secure vault (Do not commit keys to repo).

## Security notes
- Validate and rotate keys regularly.
- Use authenticated encryption (e.g., AES-GCM) to prevent tampering.
- Review cryptography library defaults before production use.

## Contributing
- Fork, create a branch, open pull requests.
- Include tests for encryption/decryption round-trips.

## License
Specify a license (e.g., MIT) in LICENSE file.