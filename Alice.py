from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os, sys
def aes_encrypt():
    # Creating public key, then writing to key.txt
    aes_key = os.urandom(16)
    with open("key.txt", "wb") as key_file:
        key_file.write(aes_key)

    # Create an AES cipher object with CBC mode
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(b'\0' * 16))
    encryptor_text = cipher.encryptor()

    # Input the message, then encrypt it
    message = input("Enter the message to encrypt: ").encode()
    ciphertext = encryptor_text.update(message) + encryptor_text.finalize()
    print("Derived Ciphertext:", ciphertext.hex())  # Convert to hexadecimal for easy printing

    # print("Alice's ciphertext sent to Bob: ", ciphertext.decode('windows-1252')) # Working comment

    # Write the ciphertext to a file
    with open("ctext.txt", "wb") as ctext_file:
        ctext_file.write(ciphertext)

def rsa_encrypt():
    pass

if sys.argv[1] == '1':
    aes_encrypt()
elif sys.argv[1] == '2':
    rsa_encrypt()
