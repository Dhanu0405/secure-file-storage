from cryptography.fernet import Fernet

def decrypt_file(file_path, encrypted_user_key, master_key_path='master.key'):
    with open(master_key_path, 'rb') as key_file:
        master_key = key_file.read()

    fernet_master = Fernet(master_key)
    user_key = fernet_master.decrypt(encrypted_user_key)
    user_fernet = Fernet(user_key)

    with open(file_path, 'rb') as f:
        encrypted_data = f.read()

    decrypted_data = user_fernet.decrypt(encrypted_data)
    return decrypted_data

def calculate_sha256(file_bytes):

    return hashlib.sha256(file_bytes).hexdigest()