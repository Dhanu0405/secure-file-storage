# Secure File Storage and Integrity Verification Web App

A simple Flask-based secure file storage system with encryption using user-specific Fernet keys. Users can register, log in, upload files (which are encrypted), and safely store them on the server.

---

## Requirements

- Python 3.10 or higher

---

## Setup Instructions

### 1. Install dependencies

It is recommended to use a virtual environment:

```bash
python -m venv venv
# On Windows:
venv\Scripts\activate
# On Mac/Linux:
source venv/bin/activate

pip install flask flask_sqlalchemy flask_login flask_bcrypt cryptography
```

### 2. Generate the master key

This key is required for encryption. Run:

```bash
python generate_master_key.py
```

This will create a file named `master.key` in your project directory.

### 3. Run the application

The database will be created automatically on first run.

```bash
python app.py
```

The app will be available at http://127.0.0.1:5000

---

## Quick Project Structure

```
File_Storage_Project/
├── app.py
├── models.py
├── utils.py
├── generate_master_key.py
├── static/
├── templates/
└── README.md
```