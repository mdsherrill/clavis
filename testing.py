from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as symmetric_padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
from cryptography.hazmat.primitives import hashes
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
    # print("Derived Ciphertext: ", ciphertext.hex()) # No longer needed for calculations
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

    # Prints the decrypted message - not needed for calculations
    # print("Received Ciphertext:", ciphertext.hex())
    # print("Decrypted message:", unpadded_message.decode())
    return unpadded_message


def rsa_encrypt(public_key, message):
    # Read Bob's public key from file
    # with open('rsa_key.txt', 'rb') as key_file:
    #     rsa_public_key = key_file.read()
    message = message.encode()

    # Create RSA Cipher
    ciphertext = public_key.encrypt(
        message,
        asymmetric_padding.OAEP(
            mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    # return ciphertext

    with open("rsa_ciphertext.txt", 'wb') as key_file:
        key_file.write(ciphertext)
    # print("Encryption to file complete.\n\nDerived Ciphertext:",
    #       ciphertext.hex())  # Convert to hexadecimal for easy printing


def rsa_decrypt(private_key):
    # Open the ciphertext file
    with open("rsa_ciphertext.txt", 'rb') as ciph_text:
        ciphertext = ciph_text.read()
    # print("Received ciphertext: ", ciphertext.hex())

    # Decrypt using ciphertext and private key
    plaintext = private_key.decrypt(
        ciphertext,
        asymmetric_padding.OAEP(
            mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # print("Decryption complete.\n\nDeciphered Message: ", plaintext)


def testing_aes_encrypt(message, bytesize):
    aes_key = create_aes_key(bytesize)
    total_time = 0.0
    for i in range(100):
        start_time = time.time()

        aes_encrypt(message, aes_key)

        end_time = time.time()
        elapsed_time = end_time - start_time
        total_time += elapsed_time
        # print(f"Elapsed time: {elapsed_time} seconds")
    avg_time = total_time / 100
    byte_size = bytesize
    print(f'Average Time for Encryption of {byte_size} bytes:', avg_time)


def testing_aes_decrypt(bytesize):
    total_time = 0.0
    for i in range(100):
        start_time = time.time()
        aes_decrypt()
        end_time = time.time()
        elapsed_time = end_time - start_time
        total_time += elapsed_time
    avg_time = total_time / 100
    byte_size = bytesize
    print(f'Average Time for Decryption of {byte_size} bytes:', avg_time)


def testing_rsa(message, bit_size):
    # First to create the RSA keys
    private_key = rsa.generate_private_key(
        public_exponent=65537,  # Always must be 65537 - Standard
        key_size=bit_size,
    )
    public_key = private_key.public_key()

    total_time = 0.0
    for i in range(100):
        start_time = time.time()

        rsa_encrypt(public_key, message)

        end_time = time.time()
        elapsed_time = end_time - start_time
        total_time += elapsed_time
        # print(f"Elapsed time: {elapsed_time} seconds")
    avg_time = total_time / 100
    print(f'Average Time for Encryption of {bit_size} bytes:', avg_time)

    total_time = 0.0
    for i in range(100):
        start_time = time.time()

        rsa_decrypt(private_key)

        end_time = time.time()
        elapsed_time = end_time - start_time
        total_time += elapsed_time
        # print(f"Elapsed time: {elapsed_time} seconds")
    avg_time = total_time / 100
    print(f'Average Time for Decryption of {bit_size} bytes:', avg_time)


if sys.argv[1] == '1':
    testing_aes_encrypt('BrookTB', 16)
    testing_aes_decrypt(16)
    testing_aes_encrypt('BrookTB', 24)
    testing_aes_decrypt(24)
    testing_aes_encrypt('BrookTB', 32)
    testing_aes_decrypt(32)
elif sys.argv[1] == '2':
    testing_rsa('BrookTB', 1024)
    testing_rsa('BrookTB', 2048)
    testing_rsa('BrookTB', 4096)
else:
    exit()
