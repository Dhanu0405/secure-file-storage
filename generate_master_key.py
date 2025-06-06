from cryptography.fernet import Fernet

# Generate a master key
master_key = Fernet.generate_key()

# Save it to a secure file
with open("master.key", "wb") as key_file:
    key_file.write(master_key)

print("Master key generated and saved as 'master.key'")