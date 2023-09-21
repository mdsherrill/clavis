from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os, sys

def aes_decrypt():
    # Read the shared secret key from a file
    with open("key.txt", "rb") as key_file:
        aes_key = key_file.read()

    # Create an AES cipher object with CBC mode
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(b'\0' * 16))
    decrypted = cipher.decryptor()

    # Read the ciphertext from the file
    with open("ctext.txt", "rb") as ctext_file:
        ciphertext = ctext_file.read()

    # Decrypt the ciphertext
    decrypted_message = decrypted.update(ciphertext) + decrypted.finalize()

    # Print the decrypted message
    print("Received Ciphertext:", ciphertext.hex())  # Print the received ciphertext in hexadecimal
    print("Decrypted message:", decrypted_message.decode())

def rsa_decrypt():
    pass

if sys.argv[1] == '1':
    aes_decrypt()
elif sys.argv[1] == '2':
    rsa_decrypt()
