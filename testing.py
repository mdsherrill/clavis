from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as symmetric_padding
from cryptography.hazmat.backends import default_backend
import sys
import os
import time


def create_aes_key(byte_size):
    # Creating public key, then writing to key.txt
    aes_key = os.urandom(byte_size)
    with open("key.txt", "wb") as key_file:
        key_file.write(aes_key)
    return aes_key

def aes_encrypt(input_message, aes_key):
    iv = os.urandom(16)
    with open("ivtext.txt", "wb") as ivtext_file:
        ivtext_file.write(iv)

    # Create an AES cipher object with CBC mode
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor_text = cipher.encryptor()

    # Input the message, then apply padding to make it a multiple of the block size
    message = input_message.encode()
    padder = symmetric_padding.PKCS7(128).padder()  # 128 bits (16 bytes) block size
    padded_message = padder.update(message) + padder.finalize()

    ciphertext = encryptor_text.update(padded_message) + encryptor_text.finalize()
    print("Derived Ciphertext: ", ciphertext.hex())

    # Write the ciphertext to a file
    with open("ctext.txt", "wb") as ctext_file:
        ctext_file.write(ciphertext)


def aes_decrypt():
    with open("ivtext.txt", "rb") as ivtext_file:
        iv = ivtext_file.read()

    # Read the shared secret key from a file
    with open("key.txt", "rb") as key_file:
        aes_key = key_file.read()

    # Create an AES cipher object with CBC mode
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # Read the ciphertext from the file
    with open("ctext.txt", "rb") as ctext_file:
        ciphertext = ctext_file.read()

    # Decrypt the ciphertext
    decrypted_message = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove PKCS7 padding
    unpadder = symmetric_padding.PKCS7(128).unpadder()
    unpadded_message = unpadder.update(decrypted_message) + unpadder.finalize()

    # Print the decrypted message
    print("Received Ciphertext:", ciphertext.hex())
    print("Decrypted message:", unpadded_message.decode())



def testing_aes():
    pass

if sys.argv[1] == '1':
    # create_aes_key(16)
    aes_encrypt('BrookandtheBluff', create_aes_key(16))
    aes_decrypt()
# elif sys.argv[1] == 'c':
#     create_rsa_key()
# elif sys.argv[1] == '2':
#     rsa_decrypt()
