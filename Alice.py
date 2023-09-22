from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding as symmetric_padding
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
# from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import os
import sys


def aes_encrypt():
    # Creating public key and iv, then writing to respective .txt files
    aes_key = os.urandom(16)
    with open("key.txt", "wb") as key_file:
        key_file.write(aes_key)
    iv = os.urandom(16)
    with open("ivtext.txt", "wb") as iv_file:
        iv_file.write(iv)

    # Create an AES cipher object with CBC mode
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor_text = cipher.encryptor()

    # Input the message, then encrypt it
    message = input("Enter the message to encrypt: ").encode()
    padder = symmetric_padding.PKCS7(128).padder()  # 128 bits (16 bytes) block size
    padded_message = padder.update(message) + padder.finalize()

    # print("Alice's ciphertext sent to Bob: ", ciphertext.decode('windows-1252')) # Working comment

    ciphertext = encryptor_text.update(padded_message) + encryptor_text.finalize()
    print("Derived Ciphertext: ", ciphertext.hex())  # Convert to hex for easy printing

    # Write the ciphertext to a file
    with open("ctext.txt", "wb") as ctext_file:
        ctext_file.write(ciphertext)


def rsa_encrypt():
    # Read Bob's public key from file
    # with open('rsa_key.txt', 'rb') as key_file:
    #     rsa_public_key = key_file.read()

    with open("rsa_public_key.txt", "rb") as key_file:
        rsa_public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )

    message = input("Enter the message to encrypt: ").encode()

    # Create RSA Cipher
    ciphertext = rsa_public_key.encrypt(
        message,
        asymmetric_padding.OAEP(
            mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    with open("rsa_ciphertext.txt", 'wb') as key_file:
        key_file.write(ciphertext)
    print("Encryption to file complete.\n\nDerived Ciphertext:",
          ciphertext.hex())  # Convert to hexadecimal for easy printing


if sys.argv[1] == '1':
    aes_encrypt()
elif sys.argv[1] == '2':
    rsa_encrypt()
