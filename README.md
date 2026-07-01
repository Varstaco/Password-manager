# Password Manager

A secure desktop password manager developed in Python using Tkinter for the graphical interface, SQLite for local storage, and AES-256-GCM encryption to securely protect user passwords.

The application allows users to create an account secured by a master password, generate strong passwords, and safely store encrypted credentials locally.

---

## Features

- User registration and authentication
- Master password protection
- AES-256-GCM password encryption
- PBKDF2-HMAC-SHA256 key derivation
- Secure local SQLite database
- Password generator with customizable options
- Password strength indicator
- Copy passwords to the clipboard
- Show or hide stored passwords
- Delete stored credentials
- Personal and Professional categories
- Unique ID generation for each entry

---

## Requirements

### Python

- Python 3.10 or newer

### Required package

```bash
pip install cryptography
```

### Standard libraries

The following libraries are included with Python and do not require installation:

- tkinter
- sqlite3
- os
- datetime
- secrets
- string
- time

---

## Installation

Clone the repository:

```bash
git clone https://github.com/yourusername/password-manager.git
```

Go to the project directory:

```bash
cd password-manager
```

Install the dependency:

```bash
pip install cryptography
```

Run the application:

```bash
python main.py
```

---

## How It Works

### 1. Account Creation

When a user creates an account:

- A random 16-byte salt is generated.
- The master password is transformed into a 256-bit encryption key using PBKDF2-HMAC-SHA256 with **390,000 iterations**.
- A verification string is encrypted using this key.
- The salt and encrypted verification value are stored inside the SQLite database.

The master password itself is **never stored**.

---

### 2. Login

When logging in:

- The user's salt is retrieved.
- The entered password is used to derive a new encryption key.
- The verification value is decrypted.
- If decryption succeeds, the user is authenticated and the encryption key is kept only for the current session.

---

### 3. Password Storage

Each password is encrypted individually using:

- AES-256-GCM
- A unique random nonce

Only encrypted passwords are stored in the database.

---

### 4. Password Retrieval

When a password is requested:

- The encrypted password and its nonce are loaded.
- They are decrypted using the current session key.
- The plaintext password is displayed or copied to the clipboard.

---

## Password Generator

The integrated password generator allows users to customize:

- Password length
- Uppercase letters
- Lowercase letters
- Numbers
- Special characters

The generator uses Python's `secrets` module for cryptographically secure randomness.

---

## Password Strength

The application evaluates password strength based on:

- Password length
- Uppercase letters
- Lowercase letters
- Digits
- Special characters

Possible ratings:

- Weak
- Medium
- High
- Very High

---

## Database Structure

### users

| Column | Description |
|---------|-------------|
| id | User ID |
| username | Username |
| salt | Random salt |
| verification_nonce | AES nonce |
| verification_ciphertext | Encrypted verification value |
| creation_date | Account creation date |

### entries

| Column | Description |
|---------|-------------|
| id | Unique entry ID |
| user_id | Owner |
| category | Personal or Professional |
| service | Website or service |
| account_username | Account username |
| nonce | AES nonce |
| encrypted_password | Encrypted password |
| creation_date | Entry creation date |

---

## Security

This project implements several security mechanisms:

- AES-256-GCM authenticated encryption
- PBKDF2-HMAC-SHA256 key derivation
- 390,000 PBKDF2 iterations
- Random salt generation
- Random nonce generation
- Secure password generation using the `secrets` module
- Master password is never stored
- Encrypted local password storage

---

## Project Structure

```
project/
│
├── main.py
├── vault.db
└── README.md
```

---

## Technologies Used

- Python
- Tkinter
- SQLite
- Cryptography
- AES-256-GCM
- PBKDF2-HMAC-SHA256

---

## Notes

This project stores all data locally. No passwords or personal information are transmitted over the internet.

The database (`vault.db`) is automatically created on first launch.

---

## License

This project is licensed under the MIT License.
