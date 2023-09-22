from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding as symmetric_padding
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import os
import sys
import time


def aes_create_key(byte_size):
    aes_key = os.urandom(int(byte_size))  # Creates random number given the byte size
    return aes_key


def aes_encrypt(input_message, aes_key):
    # Creating public key, then writing to key.txt
    # with open("key.txt", "wb") as key_file:
    #     key_file.write(aes_key)

    # Create an AES cipher object with CBC mode
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(b'\0' * 16))
    encryptor_text = cipher.encryptor()

    # Input the message, then encrypt it
    message = input_message.encode()
    padder = symmetric_padding.PKCS7(128).padder()  # 128 bits (16 bytes) block size
    padded_message = padder.update(message) + padder.finalize()

    ciphertext = encryptor_text.update(padded_message) + encryptor_text.finalize()

    # Write the ciphertext to a file
    with open("ctext.txt", "wb") as ctext_file:
        ctext_file.write(ciphertext)


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

    # Remove PKCS7 padding
    unpadder = symmetric_padding.PKCS7(128).unpadder()  # 128 bits (16 bytes) block size
    unpadded_message = unpadder.update(decrypted_message) + unpadder.finalize()

    # Print the decrypted message
    print("Decrypted message:", unpadded_message.decode())
    # print("Received Ciphertext:", ciphertext.hex())  # Print the received ciphertext in hexadecimal
    # print("Decrypted message:", decrypted_message.decode())


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
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    with open("rsa_ciphertext.txt", 'wb') as key_file:
        key_file.write(ciphertext)
    # print("Encryption to file complete.\n\nDerived Ciphertext:", ciphertext.hex())  # Convert to hexadecimal for easy printing


def create_rsa_key():
    private_key = rsa.generate_private_key(
        public_exponent=65537, # Always must be 65537 - Standard
        key_size=2048,
    )
    public_key = private_key.public_key()

    # Serialize the public key to PEM format
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(b'mypassword')
    )

    with open("rsa_public_key.txt", "wb") as key_file:
        key_file.write(public_pem)
    with open("rsa_private_key.txt", "wb") as key_file:
        key_file.write(private_pem)


def rsa_decrypt():
    # Open and read file
    with open("rsa_private_key.txt", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=b'mypassword',
        )

    # Open the ciphertext file
    with open("rsa_ciphertext.txt", 'rb') as ciph_text:
        ciphertext = ciph_text.read()
    # print("Received ciphertext: ", ciphertext.hex())

    # Decrypt using ciphertext and private key
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # print("Decryption complete.\n\nDeciphered Message: ", plaintext)


def testing_aes_encrypt(message, bytesize):
    aes_key = aes_create_key(bytesize)
    byte_size = bytesize
    total_time = 0.0
    for i in range(100):
        start_time = time.time()

        aes_encrypt(message, aes_key)

        end_time = time.time()
        elapsed_time = end_time - start_time
        total_time += elapsed_time
        # print(f"Elapsed time: {elapsed_time} seconds")
    avg_time = total_time / 100
    print(f'Average Time for Encryption of {byte_size} bytes:', avg_time)


def testing_aes_decrypt(bytesize):
    byte_size = bytesize
    total_time = 0.0
    for i in range(100):
        start_time = time.time()
        aes_decrypt()
        end_time = time.time()
        elapsed_time = end_time - start_time
        total_time += elapsed_time
    avg_time = total_time / 100
    print(f'Average Time for Encryption of {byte_size} bytes:', avg_time)


if sys.argv[1] == '1':
    aes_decrypt()
elif sys.argv[1] == 'c':
    create_rsa_key()
elif sys.argv[1] == '2':
    rsa_decrypt()
elif sys.argv[1] == 'aestest':
    # testing_aes_encrypt(sys.argv[2], sys.argv[3])
    # testing_aes_encrypt('Eightee', 16)
    testing_aes_decrypt(16)
    # testing_aes_encrypt('Eightee', 24)
    # testing_aes_encrypt('Eightee', 32)

