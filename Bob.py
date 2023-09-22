from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding as symmetric_padding
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import sys


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


def create_rsa_key():
    private_key = rsa.generate_private_key(
        public_exponent=65537,  # Always must be 65537 - Standard
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
    print("Received ciphertext: ", ciphertext.hex())

    # Decrypt using ciphertext and private key
    plaintext = private_key.decrypt(
        ciphertext,
        asymmetric_padding.OAEP(
            mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    print("Decryption complete.\n\nDeciphered Message: ", plaintext)


if sys.argv[1] == '1':
    aes_decrypt()
elif sys.argv[1] == 'c':
    create_rsa_key()
elif sys.argv[1] == '2':
    rsa_decrypt()
