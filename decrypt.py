from cryptography.fernet import Fernet
import glob
import os

def decrypt_file(encrypted_filename, key):
    with open(encrypted_filename, 'rb') as encrypted_file:
        encrypted_text = encrypted_file.read()

    cipher_suite = Fernet(key)
    decrypted_text = cipher_suite.decrypt(encrypted_text)

    # Remove the '.encrypted' extension
    decrypted_filename = encrypted_filename[:-10]

    with open(decrypted_filename, 'wb') as decrypted_file:
        decrypted_file.write(decrypted_text)

# Decrypt the encrypted file
for filename in glob.glob(os.path.join('.', "*.encrypted")):
    if os.path.isfile(filename):
        key_open = open("encryption_key.txt", "r")
        key = key_open.read().strip()
        decrypt_file(filename, key)
