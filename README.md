# secure-password-manager
Secure password manager and storage using Python and Fernet encryption
# Secure Password Manager

A command-line password manager built with Python featuring encrypted storage using Fernet symmetric encryption and PBKDF2 key derivation.

## Features

- **Strong Encryption**: Uses Fernet (AES-128) with PBKDF2-HMAC-SHA256 key derivation
- **Master Password Protection**: All passwords encrypted with user-defined master password
- **Secure Password Generation**: Configurable length and character sets
- **Password Vault**: Store, retrieve, and manage multiple passwords per service
- **Clipboard Integration**: Automatically copies generated passwords to clipboard
- **OWASP Compliant**: 480,000 PBKDF2 iterations (meets OWASP recommendations)

## Security Features

- PBKDF2 key derivation with 480,000 iterations
- Random 16-byte salt for each vault
- Encrypted storage of all password data
- No plaintext password storage
- Master password never stored

## Requirements
```
cryptography
pyperclip
```

## Installation
```bash
pip install cryptography pyperclip
```

## Usage

Run the password manager:
```bash
python Password_Generator3.py
```

The program will prompt you for a master password and provide options to:
1. Generate and store new passwords
2. Retrieve stored passwords
3. List all services
4. Delete passwords
5. Exit

## Technical Implementation

- **Encryption**: Fernet symmetric encryption (AES-128 in CBC mode with HMAC)
- **Key Derivation**: PBKDF2-HMAC-SHA256 with 480,000 iterations
- **Storage**: JSON format encrypted with derived key
- **Password Generation**: Cryptographically secure random character selection

## Project Purpose

Built as part of University of Denver Cybersecurity Boot Camp final project to demonstrate understanding of:
- Cryptographic best practices
- Secure password storage
- Python security libraries
- User authentication mechanisms

## Author

Jacob Bushbaum - Security+ Certified Cybersecurity Analyst

## License

MIT License
```
