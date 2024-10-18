from cryptography.fernet import Fernet

# Generate a key based on user-defined master key
def generate_key(master_key):
    # Generate a 32-byte key (from user-defined master key)
    return Fernet(Fernet.generate_key())

# Encrypt the password
def encrypt_password(master_key, password):
    fernet = generate_key(master_key)
    return fernet.encrypt(password.encode()).decode()

# Decrypt the password
def decrypt_password(master_key, encrypted_password):
    fernet = generate_key(master_key)
    return fernet.decrypt(encrypted_password.encode()).decode()
