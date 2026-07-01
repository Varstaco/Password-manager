# Vault - Password Manager

Vault is a secure desktop password manager developed in Python with a modern graphical interface powered by PySide6. It allows users to securely store, generate, manage, and retrieve passwords using strong cryptographic standards.

All passwords are encrypted locally using AES-256-GCM, while the master password is protected through PBKDF2-HMAC-SHA256 key derivation. No sensitive information is stored in plaintext.

---

## Features

- Secure user registration and authentication
- Master password protection
- AES-256-GCM encryption
- PBKDF2-HMAC-SHA256 key derivation
- Local SQLite database
- Modern desktop interface built with PySide6
- Secure password generator
- Password strength evaluation
- Password visibility toggle
- Copy passwords to clipboard
- Category filtering (Personal / Professional)
- Unique Vault ID generated for every entry
- Delete stored credentials
- Automatic session management

---

## Requirements

### Python

- Python 3.10 or newer

### Required packages

Install the required dependency with:

```bash
pip install cryptography PySide6
```

or

```bash
pip install -r requirements.txt
```

### requirements.txt

```text
cryptography
PySide6
```

### Standard libraries

The following modules are included with Python:

- sqlite3
- os
- sys
- secrets
- string
- time
- datetime

---

## Installation

Clone the repository:

```bash
git clone https://github.com/yourusername/vault-password-manager.git
```

Move into the project directory:

```bash
cd vault-password-manager
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Launch the application:

```bash
python main.py
```

---

## How It Works

### User Registration

When creating an account:

- A random 16-byte salt is generated.
- The master password is transformed into a 256-bit key using PBKDF2-HMAC-SHA256 with **390,000 iterations**.
- A verification string is encrypted with AES-256-GCM.
- Only the encrypted verification value and salt are stored.

The master password is never saved in the database.

---

### Authentication

During login:

- The user's salt is retrieved.
- The encryption key is derived again from the entered password.
- The verification value is decrypted.
- If the verification succeeds, the user is authenticated and the encryption key is stored only for the current session.

---

### Password Encryption

Each password is encrypted individually using:

- AES-256-GCM
- A unique random 12-byte nonce

Every stored credential has its own encryption nonce.

---

### Password Retrieval

When a password is requested:

- The encrypted data is loaded from the database.
- AES-256-GCM decrypts the password using the active session key.
- The password can either be displayed or copied directly to the clipboard.

---

## Password Generator

The built-in password generator supports:

- Custom password length (8–128 characters)
- Uppercase letters
- Lowercase letters
- Numbers
- Special characters

Random values are generated using Python's `secrets` module.

---

## Password Strength Meter

The application evaluates password strength using:

- Password length
- Uppercase characters
- Lowercase characters
- Numbers
- Symbols

Possible ratings:

- Weak
- Medium
- High
- Very High

---

## Vault Entries

Each stored credential contains:

- Unique Vault ID
- Category
- Service name
- Account username
- Encrypted password
- Creation date

Entries can be filtered by category directly from the interface.

---

## Database Structure

### users

| Column | Description |
|----------|-------------|
| id | User identifier |
| username | Account username |
| salt | Random salt |
| verification_nonce | AES nonce |
| verification_ciphertext | Encrypted verification value |
| creation_date | Account creation date |

### entries

| Column | Description |
|----------|-------------|
| id | Unique Vault ID |
| user_id | Owner |
| category | Personal or Professional |
| service | Service name |
| account_username | Account username |
| nonce | AES nonce |
| encrypted_password | Encrypted password |
| creation_date | Creation date |

---

## Security

Vault implements multiple security mechanisms:

- AES-256-GCM authenticated encryption
- PBKDF2-HMAC-SHA256
- 390,000 PBKDF2 iterations
- Random salt generation
- Random nonce generation
- Secure random password generation
- Local encrypted storage
- Master password is never stored
- Authentication based on encrypted verification data

---

## Technologies

- Python
- PySide6
- SQLite
- Cryptography
- AES-256-GCM
- PBKDF2-HMAC-SHA256

---

## Project Structure

```
vault-password-manager/
│
├── main.py
├── README.md
├── requirements.txt
├── LICENSE
├── .gitignore
├── screenshots/
└── vault.db (generated automatically)
```

---

## Screenshots

Add screenshots of the application inside the `screenshots` folder.

Example:

```
screenshots/
├── login.png
├── register.png
├── dashboard.png
└── generator.png
```

---

## Notes

- The SQLite database (`vault.db`) is automatically created when the application is launched for the first time.
- All data remains on the local machine.
- No passwords or user information are transmitted over the internet.

---

## License

This project is licensed under the MIT License.
