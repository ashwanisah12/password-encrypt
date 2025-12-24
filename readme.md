# 🔐 Glass Vault — Password Encryption Web App

Glass Vault is a client-side password encryption and decryption web application built using modern cryptographic standards. It securely encrypts sensitive passwords or text into a reusable token without sending any data to a server.

---

## 📌 Features

- Client-side encryption (no server involved)
- Secure key derivation using **PBKDF2**
- Strong encryption using **AES-GCM (256-bit)**
- Random **salt** and **IV** for every encryption
- Token-based encrypted output (`salt:iv:ciphertext`)
- Protection against brute-force and rainbow table attacks
- Local storage support (browser only)

---

## 🛠️ Technologies Used

- HTML5
- CSS3
- JavaScript (ES6)
- Web Crypto API (Browser-native cryptography)

---

## 🔑 Encryption Workflow

1. User enters secret text and a passphrase  
2. A random **salt (16 bytes)** and **IV (12 bytes)** are generated  
3. **PBKDF2** derives a cryptographic key from the passphrase  
   - Hash: SHA-256  
   - Iterations: 150,000  
4. Data is encrypted using **AES-GCM (256-bit)**  
5. Output token format (Base64 encoded):


---

## 🔓 Decryption Workflow

1. User pastes encrypted token  
2. Enters the same passphrase used during encryption  
3. PBKDF2 regenerates the key  
4. AES-GCM decrypts the ciphertext  
5. Original secret is recovered (or fails if passphrase/token is invalid)

---

## 🔒 Security Notes

- Passwords are **never stored in plain text**
- AES-GCM provides built-in authentication and integrity
- Incorrect passphrase or tampered token causes decryption failure
- All operations are performed **locally in the browser**
- Tokens saved only in **localStorage**, not on any server

---

## 🚀 How to Run

1. Download or clone the repository  
2. Open `index.html` in any modern browser  
3. Enter secret + passphrase to encrypt  
4. Copy or save the generated token  
5. Paste token and passphrase to decrypt  


## ⚠️ Disclaimer

This project is for educational purposes. While it follows recommended cryptographic practices, it should be reviewed and tested before use in production environments.

---

## 👨‍💻 Author

Developed as a cybersecurity / web security project to demonstrate secure password encryption techniques.
