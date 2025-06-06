# Secure File Storage and Integrity Verification Web App

A simple Flask-based secure file storage system with encryption using user-specific Fernet keys. Users can register, log in, upload files (which are encrypted), and safely store them on the server.

---

## Features

- User registration & login (with password hashing)
- Encrypted file storage using AES-based Fernet keys
- User-specific encryption keys (securely stored using a master key)
- File upload restrictions (type & size)
- Audit logging (planned)
- MIME type checking (planned)

---

## Dependencies

Make sure you have Python 3.10+ installed. Then install the following dependencies:

```bash
pip install flask flask_sqlalchemy flask_login flask_bcrypt cryptography

---

## Generate Master Key

```bash
python generate_master_key.py

---

## Run the App
python app.py