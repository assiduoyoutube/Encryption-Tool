from cryptography.fernet import Fernet
import argparse

parser = argparse.ArgumentParser(description="Encrypt or decrypt a file.")
parser.add_argument("action", choices=["encrypt", "decrypt"], help="Action to perform (encrypt or decrypt)")
parser.add_argument("file", help="File to operate on")

args = parser.parse_args()

if args.action == "encrypt":
    encrypt = "TRUE"
else:
    encrypt = "FALSE"

file_to_encrypt = args.file

def generate_key():
    return Fernet.generate_key()

def encrypt_file(filename, key):
    with open(filename, 'rb') as file:
        plaintext = file.read()

    cipher_suite = Fernet(key)
    encrypted_text = cipher_suite.encrypt(plaintext)

    with open(filename + '.encrypted', 'wb') as encrypted_file:
        encrypted_file.write(encrypted_text)

def decrypt_file(encrypted_filename, key):
    with open(encrypted_filename, 'rb') as encrypted_file:
        encrypted_text = encrypted_file.read()

    cipher_suite = Fernet(key)
    decrypted_text = cipher_suite.decrypt(encrypted_text)

    # Remove the '.encrypted' extension
    decrypted_filename = encrypted_filename[:-10]

    with open(decrypted_filename, 'wb') as decrypted_file:
        decrypted_file.write(decrypted_text)

encrypted_file_name = '%s.encrypted' % file_to_encrypt

if encrypt == 'TRUE':
    # Generate a key
    key = generate_key()
    save_key = open("encryption_key.txt", "w")
    print("%s" % key.decode(), file=save_key)
    save_key.close()
    # Encrypt a file
    encrypt_file(file_to_encrypt, key)
else:
    # Decrypt the encrypted file
    key_open = open("encryption_key.txt", "r")
    key = key_open.read().strip()
    decrypt_file(encrypted_file_name, key)
